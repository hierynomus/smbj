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
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.mssmb2.messages.SMB2SessionSetup;
import com.hierynomus.protocol.commons.Factory;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.security.DerivationFunction;
import com.hierynomus.security.MessageDigest;
import com.hierynomus.security.SecurityException;
import com.hierynomus.security.jce.derivationfunction.CounterDerivationParameters;
import com.hierynomus.smb.Packets;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticateResponse;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.auth.Authenticator;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.session.SMB2GuestSigningRequiredException;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.session.SessionContext;
import com.hierynomus.smbj.utils.DigestUtil;
import com.hierynomus.spnego.NegTokenInit;
import com.hierynomus.spnego.NegTokenInit2;
import com.hierynomus.spnego.SpnegoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

import static com.hierynomus.mssmb2.messages.SMB2SessionSetup.SMB2SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED;
import static com.hierynomus.mssmb2.messages.SMB2SessionSetup.SMB2SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED;
import static com.hierynomus.utils.Strings.nullTerminatedBytes;
import static java.lang.String.format;

/**
 * [MS-SMB2] 3.2.5.3.1 Handling a New Authentication
 */
public class SMBSessionBuilder {

    static final byte[] KDF_ENC_LABEL_SMB311 = nullTerminatedBytes("SMBC2SCipherKey");
    static final byte[] KDF_DEC_LABEL_SMB311 = nullTerminatedBytes("SMBS2CCipherKey");
    static final byte[] KDF_ENCDEC_LABEL = nullTerminatedBytes("SMB2AESCCM");
    static final byte[] KDF_ENC_CONTEXT = nullTerminatedBytes("ServerIn ");
    static final byte[] KDF_DEC_CONTEXT = nullTerminatedBytes("ServerOut");
    static final byte[] KDF_SIGN_CONTEXT = nullTerminatedBytes("SmbSign");
    static final byte[] KDF_SIGN_LABEL = nullTerminatedBytes("SMB2AESCMAC");
    static final byte[] KDF_SIGN_LABEL_SMB311 = nullTerminatedBytes("SMBSigningKey");
    static final byte[] KDF_APP_CONTEXT = nullTerminatedBytes("SmbRpc");
    static final byte[] KDF_APP_LABEL = nullTerminatedBytes("SMB2APP");
    static final byte[] KDF_APP_LABEL_SMB311 = nullTerminatedBytes("SMBAppKey");
    static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
    static final String AES_128_CMAC_ALGORITHM = "AesCmac";


    private static final Logger logger = LoggerFactory.getLogger(SMBSessionBuilder.class);
    private final SmbConfig config;
    private final ConnectionContext connectionContext;
    private final SessionFactory sessionFactory;
    private final SessionTable sessionTable;
    private final SessionTable preauthSessionTable;
    private final Connection connection;

    public SMBSessionBuilder(Connection connection, SmbConfig config, SessionFactory sessionFactory) {
        this.connection = connection;
        this.config = config;
        this.connectionContext = connection.getConnectionContext();
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
            BuilderContext ctx = newContext(authContext, authenticator);

            authenticator.init(config);
            processAuthenticationToken(ctx, connectionContext.getGssNegotiateToken());

            Session session = setupSession(ctx);
            logger.info("Successfully authenticated {} on {}, session is {}", authContext.getUsername(), connection.getRemoteHostname(), session.getSessionId());
            sessionTable.registerSession(session.getSessionId(), session);
            return session;
        } catch (SpnegoException | IOException e) {
            throw new SMBRuntimeException(e);
        }
    }

    private BuilderContext newContext(AuthenticationContext authContext, Authenticator authenticator) {
        BuilderContext ctx = new BuilderContext();
        ctx.authenticator = authenticator;
        ctx.authContext = authContext;
        return ctx;
    }

    private Session setupSession(BuilderContext ctx) throws IOException {
        initiateSessionSetup(ctx, ctx.securityContext);
        SMB2SessionSetup response = ctx.response;
        ctx.sessionId = response.getHeader().getSessionId();
        SMB2Dialect dialect = connectionContext.getNegotiatedProtocol().getDialect();
        if (response.getHeader().getStatusCode() == NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue()) {
            if (dialect == SMB2Dialect.SMB_3_1_1) {
                Session preauthSession = preauthSessionTable.find(ctx.sessionId);
                if (preauthSession == null) {
                    preauthSession = newSession(ctx);
                    preauthSessionTable.registerSession(ctx.sessionId, preauthSession);
                }
                updatePreauthIntegrityValue(ctx, preauthSession.getSessionContext(), ctx.request);
                updatePreauthIntegrityValue(ctx, preauthSession.getSessionContext(), ctx.response);
            }
            logger.debug("More processing required for authentication of {} using {}", ctx.authContext.getUsername(), ctx.authenticator);
            processAuthenticationToken(ctx, response.getSecurityBuffer());
            return setupSession(ctx);
        } else if (response.getHeader().getStatusCode() != NtStatus.STATUS_SUCCESS.getValue()) {
            throw new SMBApiException(response.getHeader(), format("Authentication failed for '%s' using %s", ctx.authContext.getUsername(), ctx.authenticator));
        } else {
            Session session = preauthSessionTable.find(ctx.sessionId);

            if (dialect == SMB2Dialect.SMB_3_1_1 && session != null) {
                preauthSessionTable.removeSession(session.getSessionId());
            } else {
                session = newSession(ctx);
            }

            SessionContext context = session.getSessionContext();
            processAuthenticationToken(ctx, response.getSecurityBuffer());
            context.setSessionKey(new SecretKeySpec(ctx.sessionKey, HMAC_SHA256_ALGORITHM));
            if (dialect == SMB2Dialect.SMB_3_1_1) {
                updatePreauthIntegrityValue(ctx, context, ctx.request);
            }
            validateAndSetSigning(ctx, context);

            if (dialect.isSmb3x() &&
                !response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_NULL) &&
                !response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_GUEST) &&
                connectionContext.supportsEncryption()) {
                String alg = connectionContext.getCipherId().getAlgorithmName();
                if (dialect == SMB2Dialect.SMB_3_1_1) {
                    context.setEncryptionKey(deriveKey(context.getSessionKey(), KDF_ENC_LABEL_SMB311, context.getPreauthIntegrityHashValue(), alg));
                    context.setDecryptionKey(deriveKey(context.getSessionKey(), KDF_DEC_LABEL_SMB311, context.getPreauthIntegrityHashValue(), alg));
                    context.setSigningKey(deriveKey(context.getSessionKey(), KDF_SIGN_LABEL_SMB311, context.getPreauthIntegrityHashValue(), AES_128_CMAC_ALGORITHM));
                    context.setApplicationKey(deriveKey(context.getSessionKey(), KDF_APP_LABEL_SMB311, context.getPreauthIntegrityHashValue(), alg));
                } else {
                    context.setEncryptionKey(deriveKey(context.getSessionKey(), KDF_ENCDEC_LABEL, KDF_ENC_CONTEXT, alg));
                    context.setDecryptionKey(deriveKey(context.getSessionKey(), KDF_ENCDEC_LABEL, KDF_DEC_CONTEXT, alg));
                    context.setSigningKey(deriveKey(context.getSessionKey(), KDF_SIGN_LABEL, KDF_SIGN_CONTEXT, AES_128_CMAC_ALGORITHM));
                    context.setApplicationKey(deriveKey(context.getSessionKey(), KDF_APP_LABEL, KDF_APP_CONTEXT, alg));
                }
            }
            return session;
        }
    }

    private Session newSession(BuilderContext ctx) {
        Session preauthSession;
        preauthSession = sessionFactory.createSession(ctx.authContext);
        preauthSession.setSessionId(ctx.sessionId);
        preauthSession.getSessionContext().setPreauthIntegrityHashValue(connectionContext.getPreauthIntegrityHashValue());
        return preauthSession;
    }

    private void processAuthenticationToken(BuilderContext ctx, byte[] inputToken) throws IOException {
        AuthenticateResponse resp = ctx.authenticator.authenticate(ctx.authContext, inputToken, connectionContext);
        if (resp == null) {
            return;
        }
        connectionContext.setWindowsVersion(resp.getWindowsVersion());
        connectionContext.setNetBiosName(resp.getNetBiosName());

        ctx.sessionKey = resp.getSessionKey();
        ctx.securityContext = resp.getNegToken();
    }

    private BuilderContext initiateSessionSetup(BuilderContext ctx, byte[] securityContext) throws TransportException {
        SMB2SessionSetup req = new SMB2SessionSetup(
            connectionContext.getNegotiatedProtocol().getDialect(),
            connectionContext.isServerRequiresSigning() ? EnumSet.of(SMB2_NEGOTIATE_SIGNING_REQUIRED) : EnumSet.of(SMB2_NEGOTIATE_SIGNING_ENABLED),
            connectionContext.getClientCapabilities());
        req.setSecurityBuffer(securityContext);
        req.getHeader().setSessionId(ctx.sessionId);
        ctx.request = req;
        ctx.response = connection.sendAndReceive(req);
        return ctx;
    }

    private Authenticator getAuthenticator(AuthenticationContext context) throws SpnegoException {
        List<Factory.Named<Authenticator>> supportedAuthenticators = new ArrayList<>(config.getSupportedAuthenticators());
        List<ASN1ObjectIdentifier> mechTypes = new ArrayList<>();
        if (connectionContext.getGssNegotiateToken().length > 0) {
            // The response NegTokenInit is a NegTokenInit2 according to MS-SPNG.
            NegTokenInit negTokenInit = new NegTokenInit2().read(connectionContext.getGssNegotiateToken());
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

    private void validateAndSetSigning(BuilderContext ctx, SessionContext context) {
        boolean requireMessageSigning = config.isSigningRequired();
        boolean connectionSigningRequired = connection.getConnectionContext().isServerRequiresSigning();

        // If the global setting RequireMessageSigning is set to TRUE or
        // Connection.RequireSigning is set to TRUE then Session.SigningRequired MUST be
        // set to TRUE, otherwise Session.SigningRequired MUST be set to FALSE.
        context.setSigningRequired(requireMessageSigning || connectionSigningRequired);

        if (ctx.response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_NULL)) {
            // If the security subsystem indicates that the session was established by an anonymous user, Session.SigningRequired MUST be set to FALSE.
            context.setSigningRequired(false);
        }

        boolean guest = ctx.response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_GUEST);
        if (guest && context.isSigningRequired()) {
            throw new SMB2GuestSigningRequiredException();
        } else if (guest && !requireMessageSigning) {
            context.setSigningRequired(false);
        }

        if (connection.getNegotiatedProtocol().getDialect().isSmb3x()
            && connection.getConnectionContext().supportsEncryption()
            && ctx.response.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_ENCRYPT_DATA)) {
            context.setEncryptData(true);
            context.setSigningRequired(false);
        }
    }

    private void updatePreauthIntegrityValue(BuilderContext ctx, SessionContext sessionContext, SMB2Packet packet) {
        if (ctx.digest == null) {
            String algorithmName = connection.getConnectionContext().getPreauthIntegrityHashId().getAlgorithmName();
            try {
                ctx.digest = config.getSecurityProvider().getDigest(algorithmName);
            } catch (SecurityException se) {
                throw new SMBRuntimeException("Cannot get the message digest for " + algorithmName, se);
            }
        }

        sessionContext.setPreauthIntegrityHashValue(DigestUtil.digest(ctx.digest, sessionContext.getPreauthIntegrityHashValue(), Packets.getPacketBytes(packet)));
    }

    private SecretKey deriveKey(SecretKey derivationKey, byte[] label, byte[] context, String algorithm) {
        ByteArrayOutputStream fixedSuffixTemp = new ByteArrayOutputStream(25);
        try {
            fixedSuffixTemp.write(label);
            fixedSuffixTemp.write(0);
            fixedSuffixTemp.write(context);
            fixedSuffixTemp.write(new byte[]{0x0, 0x0, 0x0, (byte) 0x80}); // 128 bits (BE byte order)
        } catch (IOException e) {
            logger.error("Unable to format suffix, error occur : ", e);
            return null;
        }
        try {
            DerivationFunction kdf = config.getSecurityProvider().getDerivationFunction("KDF/Counter/HMACSHA256");
            byte[] fixedSuffix = fixedSuffixTemp.toByteArray();
            kdf.init(new CounterDerivationParameters(derivationKey.getEncoded(), fixedSuffix, 32));
            byte[] derived = new byte[16]; // 16 bytes = 128 bits
            kdf.generateBytes(derived, 0, derived.length);
            return new SecretKeySpec(derived, algorithm);
        } catch (SecurityException se) {
            throw new SMBRuntimeException(se);
        }
    }

    public interface SessionFactory {
        Session createSession(AuthenticationContext context);
    }

    public static class BuilderContext {
        private Authenticator authenticator;
        private long sessionId;
        private byte[] sessionKey;
        private AuthenticationContext authContext;
        private byte[] securityContext;
        private SMB2SessionSetup request;
        private SMB2SessionSetup response;
        private MessageDigest digest;
    }
}
