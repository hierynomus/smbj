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
package com.hierynomus.smbj.connection;

import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.mssmb2.messages.SMB2SessionSetup;
import com.hierynomus.protocol.commons.Factory;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticateResponse;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.auth.Authenticator;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.spnego.NegTokenInit;
import com.hierynomus.spnego.NegTokenInit2;
import com.hierynomus.spnego.SpnegoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

import static com.hierynomus.mssmb2.messages.SMB2SessionSetup.SMB2SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED;
import static java.lang.String.format;

public class SMBSessionBuilder {

    private static final Logger logger = LoggerFactory.getLogger(SMBSessionBuilder.class);
    private final SmbConfig config;
    private final ConnectionInfo connectionInfo;
    private SessionFactory sessionFactory;
    private SessionTable sessionTable;
    private SessionTable preauthSessionTable;
    private Connection connection;

    public SMBSessionBuilder(Connection connection, SessionFactory sessionFactory) {
        this.connection = connection;
        this.config = connection.getConfig();
        this.connectionInfo = connection.getConnectionInfo();
        this.sessionTable = connection.getSessionTable();
        this.preauthSessionTable = connection.getPreauthSessionTable();
        this.sessionFactory = sessionFactory;
    }

    /**
     * Establish a new session on the connection using the passed credentials.
     *
     * @return a (new) Session that is authenticated for the user.
     */
    public Session establish(AuthenticationContext authContext) {
        try {
            Authenticator authenticator = getAuthenticator(authContext);
            authenticator.init(config);
            Session session = sessionFactory.createSession(authContext);
            byte[] securityContext = processAuthenticationToken(authenticator, authContext, connectionInfo.getGssNegotiateToken(), session);
            SMB2SessionSetup receive = initiateSessionSetup(securityContext, 0L);
            long preauthSessionId = receive.getHeader().getSessionId();
            if (preauthSessionId != 0L) {
                preauthSessionTable.registerSession(preauthSessionId, session);
            }
            try {
                while (receive.getHeader().getStatusCode() == NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue()) {
                    logger.debug("More processing required for authentication of {} using {}", authContext.getUsername(), authenticator);
                    securityContext = processAuthenticationToken(authenticator, authContext, receive.getSecurityBuffer(), session);
                    receive = initiateSessionSetup(securityContext, preauthSessionId);
                }

                if (receive.getHeader().getStatusCode() != NtStatus.STATUS_SUCCESS.getValue()) {
                    throw new SMBApiException(receive.getHeader(), format("Authentication failed for '%s' using %s", authContext.getUsername(), authenticator));
                }

                // Some devices only allocate the sessionId on the STATUS_SUCCESS message, not while authenticating.
                // So we need to set it on the session once we're completely authenticated.
                session.setSessionId(receive.getHeader().getSessionId());

                if (receive.getSecurityBuffer() != null) {
                    // process the last received buffer
                    processAuthenticationToken(authenticator, authContext, receive.getSecurityBuffer(), session);
                }
                session.init(receive);
                logger.info("Successfully authenticated {} on {}, session is {}", authContext.getUsername(), connection.getRemoteHostname(), session.getSessionId());
                sessionTable.registerSession(session.getSessionId(), session);
                return session;
            } finally {
                if (preauthSessionId != 0L) {
                    preauthSessionTable.sessionClosed(preauthSessionId);
                }
            }
        } catch (SpnegoException | IOException e) {
            throw new SMBRuntimeException(e);
        }
    }

    private byte[] processAuthenticationToken(Authenticator authenticator, AuthenticationContext authContext, byte[] inputToken, Session session) throws IOException {
        AuthenticateResponse resp = authenticator.authenticate(authContext, inputToken, session);
        if (resp == null) {
            return null;
        }
        connectionInfo.setWindowsVersion(resp.getWindowsVersion());
        connectionInfo.setNetBiosName(resp.getNetBiosName());
        byte[] securityContext = resp.getNegToken();
        if (resp.getSigningKey() != null) {
            session.setSigningKey(resp.getSigningKey());
        }
        return securityContext;
    }

    private SMB2SessionSetup initiateSessionSetup(byte[] securityContext, long sessionId) throws TransportException {
        SMB2SessionSetup req = new SMB2SessionSetup(
            connectionInfo.getNegotiatedProtocol().getDialect(),
            EnumSet.of(SMB2_NEGOTIATE_SIGNING_ENABLED),
            connectionInfo.getClientCapabilities());
        req.setSecurityBuffer(securityContext);
        req.getHeader().setSessionId(sessionId);
        return connection.sendAndReceive(req);
    }

    private Authenticator getAuthenticator(AuthenticationContext context) throws SpnegoException {
        List<Factory.Named<Authenticator>> supportedAuthenticators = new ArrayList<>(config.getSupportedAuthenticators());
        List<ASN1ObjectIdentifier> mechTypes = new ArrayList<>();
        if (connectionInfo.getGssNegotiateToken().length > 0) {
            // The response NegTokenInit is a NegTokenInit2 according to MS-SPNG.
            NegTokenInit negTokenInit = new NegTokenInit2().read(connectionInfo.getGssNegotiateToken());
            mechTypes = negTokenInit.getSupportedMechTypes();
        }

        for (Factory.Named<Authenticator> factory : new ArrayList<>(supportedAuthenticators)) {
            if (mechTypes.isEmpty() || mechTypes.contains(new ASN1ObjectIdentifier(factory.getName()))) {
                Authenticator authenticator = factory.create();
                if (authenticator.supports(context)) {
                    return authenticator;
                }
            }
        }

        throw new SMBRuntimeException("Could not find a configured authenticator for mechtypes: " + mechTypes + " and authentication context: " + context);
    }

    public interface SessionFactory {
        Session createSession(AuthenticationContext context);
    }
}
