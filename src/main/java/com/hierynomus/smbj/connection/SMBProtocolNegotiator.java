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
import com.hierynomus.mssmb2.messages.negotiate.SMB2EncryptionCapabilities;
import com.hierynomus.mssmb2.messages.negotiate.SMB2NegotiateContext;
import com.hierynomus.mssmb2.messages.negotiate.SMB2PreauthIntegrityCapabilities;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.security.MessageDigest;
import com.hierynomus.security.SecurityException;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.utils.DigestUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Handles the protocol negotiation.
 */
class SMBProtocolNegotiator {
    private static final Logger logger = LoggerFactory.getLogger(SMBProtocolNegotiator.class);
    private final SmbConfig config;
    private final ConnectionInfo connectionInfo;
    private Connection connection;
    private NegotiationContext negotiationContext = new NegotiationContext();

    public SMBProtocolNegotiator(Connection connection) {
        this.connection = connection;
        this.config = connection.getConfig();
        this.connectionInfo = connection.getConnectionInfo();
    }

    void negotiateDialect() throws TransportException {
        logger.debug("Negotiating dialects {} with server {}", config.getSupportedDialects(), connection.getRemoteHostname());
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

        connectionInfo.negotiated(negotiationContext);
        logger.debug("Negotiated the following connection settings: {}", connectionInfo);
    }

    private void initializeNegotiationContext() {
        // if dialect is 3.1.1, read the NegotiateContextList. Otherwise, using the default.
        SMB2Dialect dialect = negotiationContext.negotiationResponse.getDialect();
        if (dialect == SMB2Dialect.SMB_3_1_1) {
            List<SMB2NegotiateContext> negotiateContextList = this.negotiationContext.negotiationResponse.getNegotiateContextList();
            if (negotiateContextList != null) {
                for (SMB2NegotiateContext negotiateContext: negotiateContextList) {
                    switch (negotiateContext.getNegotiateContextType()) {
                        case SMB2_PREAUTH_INTEGRITY_CAPABILITIES: {
                            negotiationContext.preauthIntegrityHashId = getHashAlgorithm((SMB2PreauthIntegrityCapabilities) negotiateContext);
                            negotiationContext.preauthIntegrityHashValue = calculatePreauthHashValue();

                            break;
                        }
                        case SMB2_ENCRYPTION_CAPABILITIES: {
                            SMB2EncryptionCapabilities encryptionCapabilitiesResponse = (SMB2EncryptionCapabilities) negotiateContext;
                            List<SMB3EncryptionCipher> cipherList = encryptionCapabilitiesResponse.getCipherList();
                            if (cipherList.size() != 1) {
                                throw new IllegalStateException("The SMB2EncryptionCapabilities NegotiateContext does not contain exactly 1 cipher");
                            }
                            negotiationContext.cipher = cipherList.get(0);
                            break;
                        }
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

    private SMB3HashAlgorithm getHashAlgorithm(SMB2PreauthIntegrityCapabilities negotiateContext) {
        if (negotiateContext.getHashAlgorithms().size() != 1) {
            throw new IllegalStateException("There should be exactly 1 hash algorithm set.");
        }
        SMB3HashAlgorithm hashAlgorithm = negotiateContext.getHashAlgorithms().get(0);

        if (hashAlgorithm == null) {
            logger.error("Unable to read hashAlgorithm from SMB2PreauthIntegrityCapabilities in SMB2NegotiateResponse.");
            throw new IllegalStateException("Unable to read hashAlgorithm from SMB2PreauthIntegrityCapabilities in SMB2NegotiateResponse.");
        }
        return hashAlgorithm;
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
        SMB2Packet negotiatePacket = new SMB2NegotiateRequest(config.getSupportedDialects(), connectionInfo.getClientGuid(), config.isSigningRequired(), config.getClientCapabilities());
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

    /**
     * Get the serialized packet bytes.
     * @param packet
     * @return
     * @throws Buffer.BufferException
     */
    private byte[] getPacketBytes(SMBPacket packet) {
        SMBBuffer buffer = packet.getBuffer();
        int originalPos = buffer.rpos();
        buffer.rpos(packet.getMessageStartPos());
        byte[] packetBytes = new byte[packet.getMessageEndPos() - packet.getMessageStartPos()]; // Allocate large enough byte[] for message
        try {
            buffer.readRawBytes(packetBytes);
        } catch (Buffer.BufferException be) {
            throw new SMBRuntimeException("Cannot read packet bytes from buffer", be);
        }
        buffer.rpos(originalPos);
        return packetBytes;
    }

    public static class NegotiationContext {
        private SMBPacket negotiationRequest;
        private SMB2NegotiateResponse negotiationResponse;
        private SMB3EncryptionCipher cipher;
        private SMB3HashAlgorithm preauthIntegrityHashId;
        private byte[] preauthIntegrityHashValue;

        public SMBPacket getNegotiationRequest() {
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

        public byte[] getPreauthIntegrityHashValue() {
            return preauthIntegrityHashValue;
        }
    }
}
