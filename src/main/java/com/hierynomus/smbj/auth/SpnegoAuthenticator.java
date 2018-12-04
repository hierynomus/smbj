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

import com.hierynomus.mssmb2.SMB2Header;
import com.hierynomus.protocol.commons.ByteArrayUtils;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.smbj.GSSContextConfig;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.session.Session;
import org.ietf.jgss.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import java.io.IOException;
import java.security.Key;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.Random;


public class SpnegoAuthenticator implements Authenticator {
    private static final Logger logger = LoggerFactory.getLogger(SpnegoAuthenticator.class);
    private GSSContextConfig gssContextConfig;

    public static class Factory implements com.hierynomus.protocol.commons.Factory.Named<Authenticator> {

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

    private GSSContext gssContext;

    @Override
    public AuthenticateResponse authenticate(final AuthenticationContext context, final byte[] gssToken, final Session session) throws IOException {
        final GSSAuthenticationContext gssAuthenticationContext = (GSSAuthenticationContext) context;
        try {
            return Subject.doAs(gssAuthenticationContext.getSubject(), new PrivilegedExceptionAction<AuthenticateResponse>() {
                public AuthenticateResponse run() throws Exception {
                    return authenticateSession(gssAuthenticationContext, gssToken, session);
                }
            });
        } catch (PrivilegedActionException e) {
            throw new TransportException(e);
        }
    }

    private AuthenticateResponse authenticateSession(GSSAuthenticationContext context, byte[] gssToken, Session session) throws TransportException {
        try {
            logger.debug("Authenticating {} on {} using SPNEGO", context.getUsername(), session.getConnection().getRemoteHostname());
            if (gssContext == null) {
                GSSManager gssManager = GSSManager.getInstance();
                Oid spnegoOid = new Oid("1.3.6.1.5.5.2"); //SPNEGO

                String service = "cifs";
                String hostName = session.getConnection().getRemoteHostname();
                GSSName serverName = gssManager.createName(service + "@" + hostName, GSSName.NT_HOSTBASED_SERVICE);
                gssContext = gssManager.createContext(serverName, spnegoOid, context.getCreds(), GSSContext.DEFAULT_LIFETIME);
                gssContext.requestMutualAuth(gssContextConfig.isRequestMutualAuth());
                gssContext.requestCredDeleg(gssContextConfig.isRequestCredDeleg());
                // TODO fill in all the other options too
            }

            byte[] newToken = gssContext.initSecContext(gssToken, 0, gssToken.length);

            if (newToken != null) {
                logger.trace("Received token: {}", ByteArrayUtils.printHex(newToken));
            }

            AuthenticateResponse response = new AuthenticateResponse(newToken);
            if (gssContext.isEstablished()) {
                Key key = ExtendedGSSContext.krb5GetSessionKey(gssContext);
                if (key != null) {
                    // if a session key was negotiated, save it.
                    response.setSigningKey(adjustSessionKeyLength(key.getEncoded()));
                }
            }
            return response;
        } catch (GSSException e) {
            throw new TransportException(e);
        }
    }

    /**
     * [MS-SMB2] 3.2.5.3.1 Handling a New Authentication
     * Session.SessionKey MUST be set to the first 16 bytes of the cryptographic key queried from the
     * GSS protocol for this authenticated context. If the cryptographic key is less than 16 bytes,
     * it is right-padded with zero bytes.
     *
     * @param key session key from the GSS API
     * @return key, truncated or padded to 16 bytes
     */
    private byte[] adjustSessionKeyLength(byte[] key) {
        byte[] newKey;
        if (key.length > SMB2Header.SIGNATURE_SIZE) {
            newKey = Arrays.copyOfRange(key, 0, SMB2Header.SIGNATURE_SIZE);
        } else if (key.length < SMB2Header.SIGNATURE_SIZE) {
            newKey = new byte[16];
            System.arraycopy(key, 0, newKey, 0, key.length);
            Arrays.fill(newKey, key.length, SMB2Header.SIGNATURE_SIZE - 1, (byte) 0);
        } else {
            newKey = key;
        }
        return newKey;
    }

    @Override
    public void init(SmbConfig config) {
        this.gssContextConfig = config.getClientGSSContextConfig();
    }

    @Override
    public boolean supports(AuthenticationContext context) {
        return context.getClass().equals(GSSAuthenticationContext.class);
    }
}
