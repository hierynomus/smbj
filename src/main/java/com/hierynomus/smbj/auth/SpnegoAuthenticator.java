/*
 * Copyright (C)2016 - SMBJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.hierynomus.smbj.auth;

import java.io.IOException;
import java.security.Key;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.EnumSet;
import java.util.concurrent.Future;
import java.util.Arrays;

import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Subject;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2Header;
import com.hierynomus.mssmb2.messages.SMB2SessionSetup;
import com.hierynomus.protocol.commons.ByteArrayUtils;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.common.MessageSigning;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.TransportException;
import com.hierynomus.spnego.SpnegoException;
import com.sun.security.jgss.ExtendedGSSContext;
import com.sun.security.jgss.InquireType;

public class SpnegoAuthenticator implements Authenticator {
    private static final Logger logger = LoggerFactory.getLogger(SpnegoAuthenticator.class);

    private byte[] sessionKey;

    public static class Factory implements com.hierynomus.protocol.commons.Factory.Named<SpnegoAuthenticator> {

        @Override
        public String getName() {
            // The OID for NEGOEX (Extended SPNEGO)
            return "1.3.6.1.4.1.311.2.2.30";
        }

        @Override
        public SpnegoAuthenticator create() {
            return new SpnegoAuthenticator();
        }
    }

    public Session authenticate(final Connection connection, final GSSAuthenticationContext context) throws TransportException {
        try {
            Session session = Subject.doAs(context.getSubject(), new PrivilegedExceptionAction<Session>(){
                public Session run() throws Exception{
                    return authenticateSession(context.getCreds(), connection, context);
                }
            });
            return session;
        } catch (PrivilegedActionException e) {
            throw new TransportException(e);
        }
    }
    
    // called to execute the session-setup sequence.  Called after the SMB negotiation.
    //
    private Session authenticateSession(GSSCredential clientCreds, Connection connection, AuthenticationContext context) throws TransportException {
        Session session = null; 
        try {
            logger.info("Authenticating {} on {} using SPNEGO", context.getUsername(), connection.getRemoteHostname());
            EnumSet<SMB2SessionSetup.SMB2SecurityMode> signingEnabled = EnumSet.of
                    (SMB2SessionSetup.SMB2SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED);
            byte[] gssToken = connection.getConnectionInfo().getGssNegotiateToken();
            if (gssToken == null) {
                logger.error("GSS token is null, but should have been provided by the SMB negotiation response");
            }
            
            GSSManager gssManager = GSSManager.getInstance();
            Oid spnegoOid = new Oid("1.3.6.1.5.5.2"); //SPNEGO
            
            String service = "cifs";
            String hostName = connection.getRemoteHostname();
            GSSName serverName = gssManager.createName(service+"@"+hostName, GSSName.NT_HOSTBASED_SERVICE);
            GSSContext gssContext = gssManager.createContext(serverName, spnegoOid, clientCreds, GSSContext.DEFAULT_LIFETIME);
            gssContext.requestMutualAuth(false);
            // TODO: fill in all the other options too
            
            long sessionId = 0;
            while (true) {
                gssToken = gssContext.initSecContext(gssToken, 0, gssToken.length);
                if (gssToken != null) {
                    // create the setup message
                    SMB2SessionSetup smb2SessionSetup = new SMB2SessionSetup(connection.getNegotiatedProtocol().getDialect(), signingEnabled);
                    smb2SessionSetup.getHeader().setSessionId(sessionId);
                    smb2SessionSetup.setSecurityBuffer(gssToken);
                    // send the setup message
                    Future<SMB2SessionSetup> future = connection.send(smb2SessionSetup);
                    // retrieve setup response
                    SMB2SessionSetup receive = Futures.get(future, TransportException.Wrapper);
                    
                    if (receive.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                        throw new SpnegoException("Setup failed with " + receive.getHeader().getStatus());
                    }
                
                    //TODO: check receive for error?
                    gssToken = receive.getSecurityBuffer();
                    if (sessionId == 0) {
                        sessionId = receive.getHeader().getSessionId();
                        session = new Session(sessionId, connection);
                        connection.getConnectionInfo().getPreauthSessionTable().registerSession(sessionId, session);
                    }

                    logger.debug("Received token: {}", ByteArrayUtils.printHex(gssToken));
                }
                if (gssContext.isEstablished())
                    break;
            }
            
            ExtendedGSSContext e = (ExtendedGSSContext)gssContext;
            Key key = (Key)e.inquireSecContext(InquireType.KRB5_GET_SESSION_KEY);
            if (key != null) {
                // if a session key was negotiated, save it.
                sessionKey = adjustKeyLength(key.getEncoded());
                session.setSigningKeySpec(new SecretKeySpec(sessionKey, MessageSigning.HMAC_SHA256_ALGORITHM));
            }
            return session;
        } catch (IOException | GSSException e) {
            throw new TransportException(e);
        } finally {
            // remove the session from the preauth session table
            if (session != null) {
                connection.getConnectionInfo().getPreauthSessionTable().sessionClosed(session.getSessionId());
            }
        }
    }

    /**
     * Make sure the key is exactly 16 bytes long.
     * @param key session key from the GSS API 
     * @return key, truncated or padded to 16 bytes
     */
    private byte[] adjustKeyLength(byte[] key) {
        // [MS-SMB2] 3.2.5.3.1 Handling a New Authentication
        // Session.SessionKey MUST be set to the first 16 bytes of the cryptographic key queried from the 
        // GSS protocol for this authenticated context. If the cryptographic key is less than 16 bytes, 
        // it is right-padded with zero bytes.
        
        byte[] newKey;
        if (key.length > SMB2Header.SIGNATURE_SIZE) {
            newKey = Arrays.copyOfRange(key, 0, SMB2Header.SIGNATURE_SIZE);
        }
        else if (key.length < SMB2Header.SIGNATURE_SIZE) {
            newKey = new byte[16];
            System.arraycopy(key, 0, newKey, 0, key.length);
            Arrays.fill(newKey,  key.length, SMB2Header.SIGNATURE_SIZE-1, (byte)0);
        }
        else {
            newKey = key;
        }
        return newKey;
    }

    public byte[] getSessionKey() {
        return sessionKey;
    }
}
