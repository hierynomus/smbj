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

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb.SMB1Packet;
import com.hierynomus.mssmb.messages.SMB1ComNegotiateRequest;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2NegotiateRequest;
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse;
import com.hierynomus.mssmb2.messages.negotiate.SMB2CompressionCapabilities;
import com.hierynomus.mssmb2.messages.negotiate.SMB2EncryptionCapabilities;
import com.hierynomus.mssmb2.messages.negotiate.SMB2NegotiateContext;
import com.hierynomus.mssmb2.messages.negotiate.SMB2PreauthIntegrityCapabilities;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.security.MessageDigest;
import com.hierynomus.security.SecurityException;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.server.Server;
import com.hierynomus.smbj.utils.DigestUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static com.hierynomus.smb.Packets.getPacketBytes;

/**
 * Handles the protocol negotiation.
 */
class SMBProtocolNegotiator {
    private static final Logger logger = LoggerFactory.getLogger(SMBProtocolNegotiator.class);
    private final SmbConfig config;
    private final ConnectionContext connectionContext;
    private Connection connection;
    private NegotiationContext negotiationContext = new NegotiationContext();
    // [MS-SMB2] <103> Section 3.2.4.2.2.2: Windows 10, Windows Server 2016, and Windows Server operating
    // system use 32 bytes of Salt.
    private static final int SALT_LENGTH = 32;

    public SMBProtocolNegotiator(Connection connection, SmbConfig config, ConnectionContext connectionContext) {
        this.connection = connection;
        this.config = config;
        this.connectionContext = connectionContext;
    }

    void negotiateDialect() throws TransportException {
        logger.debug("Negotiating dialects {}", config.getSupportedDialects());
        SMB2NegotiateResponse resp;
        if (config.isUseMultiProtocolNegotiate()) {
            resp = multiProtocolNegotiate();
        } else {
            resp = smb2OnlyNegotiate();
        }
        this.negotiationContext.negotiationResponse = resp;

        if (!NtStatus.isSuccess(resp.getHeader().getStatusCode())) {
            throw new SMBApiException(resp.getHeader(), "Failure during dialect negotiation");
        }

        initializeNegotiationContext();
        initializeOrValidateServerDetails();
        connectionContext.negotiated(negotiationContext);
        logger.debug("Negotiated the following connection settings: {}", connectionContext);
    }

    private void initializeNegotiationContext() {
        // if dialect is 3.1.1, read the NegotiateContextList. Otherwise, using the default.
        SMB2Dialect dialect = negotiationContext.negotiationResponse.getDialect();
        if (dialect == SMB2Dialect.SMB_3_1_1) {
            List<SMB2NegotiateContext> negotiateContextList = this.negotiationContext.negotiationResponse.getNegotiateContextList();
            if (negotiateContextList != null) {
                boolean seenPreAuth = false;
                boolean seenEncryption = false;
                boolean seenCompression = false;
                for (SMB2NegotiateContext negotiateContext: negotiateContextList) {
                    switch (negotiateContext.getNegotiateContextType()) {
                        case SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
                            if (seenPreAuth) {
                                throw new IllegalStateException("SMB2_PREAUTH_INTEGRITY_CAPABILITIES should only appear once in the NegotiateContextList");
                            }
                            seenPreAuth = true;
                            handlePreAuthNegotiateContext((SMB2PreauthIntegrityCapabilities) negotiateContext);
                            break;
                        case SMB2_ENCRYPTION_CAPABILITIES:
                            if (seenEncryption) {
                                throw new IllegalStateException("SMB2_ENCRYPTION_CAPABILITIES should only appear once in the NegotiateContextList");
                            }
                            seenEncryption = true;
                            handleEncryptionNegotiateContext((SMB2EncryptionCapabilities) negotiateContext);
                            break;
                        case SMB2_COMPRESSION_CAPABILITIES:
                            if (seenCompression) {
                                throw new IllegalStateException("SMB2_COMPRESSION_CAPABILITIES should only appear once in the NegotiateContextList");
                            }
                            seenCompression = true;
                            handleCompressionNegotiateContext((SMB2CompressionCapabilities) negotiateContext);
                            break;
                        default:
                            throw new IllegalStateException("unknown negotiate context type");
                    }
                }
            } else {
                throw new IllegalStateException("negotiate context list is null for SMB 3.1.1 dialect");
            }
        } else {
            // Set the cipherId for SMB 3.0.x dialect.
            if (dialect.isSmb3x() && negotiationContext.negotiationResponse.getCapabilities().contains(SMB2GlobalCapability.SMB2_GLOBAL_CAP_ENCRYPTION)) {
                negotiationContext.cipher = SMB3EncryptionCipher.AES_128_CCM;
            }
        }
    }

    private void handleCompressionNegotiateContext(SMB2CompressionCapabilities negotiateContext) {
        List<SMB3CompressionAlgorithm> compressionAlgorithms = negotiateContext.getCompressionAlgorithms();
        if (compressionAlgorithms.size() == 0) {
            throw new IllegalStateException("The SMB2CompressionCapabilities NegotiateContext should contain at least 1 algorithm");
        } else if (compressionAlgorithms.size() == 1 && compressionAlgorithms.get(0) == SMB3CompressionAlgorithm.NONE) {
            logger.info("SMB3CompressionAlgorithm is 'NONE', continuing without compression");
            return;
        }

        // TODO flags CHAINED
        negotiationContext.compressionIds = EnumSet.copyOf(compressionAlgorithms);
    }

    private void handleEncryptionNegotiateContext(SMB2EncryptionCapabilities negotiateContext) {
        List<SMB3EncryptionCipher> cipherList = negotiateContext.getCipherList();
        if (cipherList.size() != 1) {
            throw new IllegalStateException("The SMB2EncryptionCapabilities NegotiateContext does not contain exactly 1 cipher");
        }
        negotiationContext.cipher = cipherList.get(0);
    }

    private void handlePreAuthNegotiateContext(SMB2PreauthIntegrityCapabilities negotiateContext) {
        if (negotiateContext.getHashAlgorithms().size() != 1) {
            throw new IllegalStateException("The SMB2PreauthIntegrityCapabilities NegotiateContext does not contain exactly 1 hash algorithm");
        }
        SMB3HashAlgorithm hashAlgorithm = negotiateContext.getHashAlgorithms().get(0);

        negotiationContext.preauthIntegrityHashId = hashAlgorithm;
        negotiationContext.preauthIntegrityHashValue = calculatePreauthHashValue();
    }

    private byte[] calculatePreauthHashValue() {
        // get the requestBytes and responseBytes
        byte[] requestBytes = getPacketBytes(negotiationContext.negotiationRequest);
        byte[] responseBytes = getPacketBytes(negotiationContext.negotiationResponse);

        MessageDigest messageDigest;
        String algorithmName = negotiationContext.preauthIntegrityHashId.getAlgorithmName();
        try {
            messageDigest = config.getSecurityProvider().getDigest(algorithmName);
        } catch (SecurityException se) {
            throw new SMBRuntimeException("Cannot get the message digest for " + algorithmName, se);
        }
        // 3.2.5.2 Receiving an SMB2 NEGOTIATE Response, client MUST initialize Connection.PreauthIntegrityHashValue with zero
        // initialize with zero (length is depends on the digest algorithm)
        byte[] hashValue = new byte[messageDigest.getDigestLength()];
        // concatenating the initial value and negotiateRequestBytes then digest
        hashValue = DigestUtil.digest(messageDigest, hashValue, requestBytes);
        // concatenating the previous value and negotiateResponseBytes then digest
        hashValue = DigestUtil.digest(messageDigest, hashValue, responseBytes);
        return hashValue;
    }


    private SMB2NegotiateResponse smb2OnlyNegotiate() throws TransportException {
        byte[] salt = new byte[32];
        config.getRandomProvider().nextBytes(salt);
        SMB2Packet negotiatePacket = new SMB2NegotiateRequest(config.getSupportedDialects(), connectionContext.getClientGuid(), config.isSigningRequired(), config.getClientCapabilities(), salt);
        this.negotiationContext.negotiationRequest = negotiatePacket;
        return connection.sendAndReceive(negotiatePacket);
    }

    private SMB2NegotiateResponse multiProtocolNegotiate() throws TransportException {
        SMB1Packet negotiatePacket = new SMB1ComNegotiateRequest(config.getSupportedDialects());
        long l = connection.sequenceWindow.get();
        if (l != 0) {
            throw new IllegalStateException("The SMBv1 SMB_COM_NEGOTIATE packet needs to be the first packet sent.");
        }
        Request request = new Request(negotiatePacket, l, UUID.randomUUID());
        connection.outstandingRequests.registerOutstanding(request);
        this.negotiationContext.negotiationRequest = negotiatePacket;
        connection.transport.write(negotiatePacket);
        Future<SMB2Packet> future = request.getFuture(null);
        SMB2Packet packet = Futures.get(future, config.getTransactTimeout(), TimeUnit.MILLISECONDS, TransportException.Wrapper);
        if (!(packet instanceof SMB2NegotiateResponse)) {
            throw new IllegalStateException("Expected a SMB2 NEGOTIATE Response to our SMB_COM_NEGOTIATE, but got: " + packet);
        }
        SMB2NegotiateResponse negotiateResponse = (SMB2NegotiateResponse) packet;

        if (negotiateResponse.getDialect() == SMB2Dialect.SMB_2XX) {
            return smb2OnlyNegotiate();
        }
        return negotiateResponse;
    }

    private void initializeOrValidateServerDetails() throws TransportException {
        Server temp = connectionContext.getServer();
        SMB2NegotiateResponse response = negotiationContext.negotiationResponse;
        temp.init(response.getServerGuid(), response.getDialect(), response.getSecurityMode(), response.getCapabilities());

        Server cachedServer = connection.serverList.lookup(temp.getServerName());
        if (cachedServer == null) {
            connection.serverList.registerServer(temp);
            negotiationContext.server = temp;
        } else if (temp.validate(cachedServer)) {
            negotiationContext.server = cachedServer;
        } else {
            throw new TransportException(String.format("Different server found for same hostname '%s', disconnecting...", temp.getServerName()));
        }
    }

    public static class NegotiationContext {
        private SMBPacket<?, ?> negotiationRequest;
        private SMB2NegotiateResponse negotiationResponse;
        private SMB3EncryptionCipher cipher;
        private SMB3HashAlgorithm preauthIntegrityHashId;
        private Set<SMB3CompressionAlgorithm> compressionIds = EnumSet.noneOf(SMB3CompressionAlgorithm.class);
        private byte[] preauthIntegrityHashValue;
        private Server server;

        public SMBPacket<?, ?> getNegotiationRequest() {
            return negotiationRequest;
        }

        public SMB2NegotiateResponse getNegotiationResponse() {
            return negotiationResponse;
        }

        public SMB3EncryptionCipher getCipher() {
            return cipher;
        }

        public SMB3HashAlgorithm getPreauthIntegrityHashId() {
            return preauthIntegrityHashId;
        }

        public Set<SMB3CompressionAlgorithm> getCompressionIds() {
            return compressionIds;
        }

        public Server getServer() {
            return server;
        }

        public byte[] getPreauthIntegrityHashValue() {
            return preauthIntegrityHashValue;
        }
    }
}
