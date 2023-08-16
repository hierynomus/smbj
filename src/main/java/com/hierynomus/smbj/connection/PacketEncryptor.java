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

import com.hierynomus.mssmb2.*;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.security.AEADBlockCipher;
import com.hierynomus.security.Cipher;
import com.hierynomus.security.SecurityException;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.common.SMBRuntimeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

public class PacketEncryptor {
    private static final Logger logger = LoggerFactory.getLogger(PacketEncryptor.class);
    private SecurityProvider securityProvider;
    private SMB3EncryptionCipher cipher;
    private SMB2Dialect dialect;
    private AtomicInteger nonceCounter = new AtomicInteger(0);

    public PacketEncryptor(SecurityProvider securityProvider) {
        this.securityProvider = securityProvider;
    }

    void init(ConnectionContext connectionContext) {
        this.dialect = connectionContext.getNegotiatedProtocol().getDialect();
        // The client MUST decrypt the message using Session.DecryptionKey. If Connection.Dialect is "3.1.1", the algorithm
        // specified by Connection.CipherId is used. Otherwise, the AES-128-CCM algorithm is used.
        if (connectionContext.getNegotiatedProtocol().getDialect().equals(SMB2Dialect.SMB_3_1_1)) {
            cipher = connectionContext.getCipherId();
        } else {
            cipher = SMB3EncryptionCipher.AES_128_CCM;
        }
        logger.info("Initialized PacketEncryptor with Cipher << {} >>", cipher);
    }

    public boolean canDecrypt(SMB3EncryptedPacketData packetData) {
        return dialect.isSmb3x()
            && packetData.getDataBuffer().available() != 0 // SMBPacketData eagerly reads the header, so if no data left, fail.
            && packetData.getHeader().getFlagsEncryptionAlgorithm() == 0x01;
    }

    public byte[] decrypt(SMB3EncryptedPacketData packetData, SecretKey decryptionKey) {
        byte[] realNonce = Arrays.copyOf(packetData.getHeader().getNonce(), cipher.getNonceLength());
        try {
            byte[] aad = createAAD(packetData.getHeader());
            byte[] cipherText = packetData.getCipherText();
            byte[] signature = packetData.getHeader().getSignature();

            AEADBlockCipher aeadBlockCipher = securityProvider.getAEADBlockCipher(cipher.getAlgorithmName());
            aeadBlockCipher.init(Cipher.CryptMode.DECRYPT, decryptionKey.getEncoded(), new GCMParameterSpec(128, realNonce));
            aeadBlockCipher.updateAAD(aad, 0, aad.length);
            byte[] bytes = aeadBlockCipher.update(cipherText, 0, cipherText.length);
            byte[] bytes2 = aeadBlockCipher.doFinal(signature, 0, signature.length);
            if (bytes != null && bytes.length != 0) {
                byte[] decrypted = new byte[bytes.length + bytes2.length];
                System.arraycopy(bytes, 0, decrypted, 0, bytes.length);
                System.arraycopy(bytes2, 0, decrypted, bytes.length, bytes2.length);
                return decrypted;
            } else {
                return bytes2;
            }
        } catch (SecurityException e) {
            logger.error("Security exception while decrypting packet << {} >>", packetData);
            throw new SMBRuntimeException(e);
        } catch (Buffer.BufferException be) {
            logger.error("Could not read cipherText from packet << {} >>", packetData);
            throw new SMBRuntimeException("Could not read cipherText from packet", be);
        }
    }

    public SMB2Packet encrypt(SMB2Packet packet, SecretKey encryptionKey) {
        if (encryptionKey != null) {
            return new EncryptedPacketWrapper(packet, encryptionKey);
        } else {
            logger.debug("Not wrapping {} as encrypted, as no key is set.", packet.getHeader().getMessage());
            return packet;
        }
    }

    byte[] createAAD(SMB2TransformHeader header) {
        SMBBuffer b = new SMBBuffer();
        header.writeTo(b); // Write the header
        b.rpos(20); // Skip ProtocolId (4 bytes) AND Signature (16 bytes)
        return b.getCompactData();
    }

    byte[] getNewNonce() {
        long nonce = System.nanoTime();
        SMBBuffer b = new SMBBuffer();
        b.putUInt64(nonce); // Little Endians go first
        int padding = cipher.getNonceLength() - 8; // 64 bits = 8 bytes
        b.putReserved(padding);
        return b.getCompactData();
    }

    public void setCipher(SMB3EncryptionCipher cipher) {
        this.cipher = cipher;
    }

    public class EncryptedPacketWrapper extends SMB2Packet {
        private final SMB2Packet packet;
        private final SecretKey encryptionKey;

        public EncryptedPacketWrapper(SMB2Packet packet, SecretKey encryptionKey) {
            this.packet = packet;
            this.encryptionKey = encryptionKey;
        }

        @Override
        public void write(SMBBuffer buffer) {
            SMBBuffer wrappedPacketPlain = new SMBBuffer();
            // Write the whole plainText packet to the buffer
            packet.write(wrappedPacketPlain);

            // number of bytes available to read is equals to packet size
            final byte[] plainText = wrappedPacketPlain.getCompactData();

            // The nonce used in the SMB2_TRANSFORM_HEADER
            final byte[] nonceField = getNewNonce();
            // the nonce actually used in encryption
            final GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonceField);

            // 3.1.4.3 Encrypting the Message, The SMB2 TRANSFORM_HEADER,
            // excluding the ProtocolId and Signature fields,
            // as the optional authenticated data.
            SMB2TransformHeader header = new SMB2TransformHeader(nonceField, plainText.length, packet.getHeader().getSessionId());
            final byte[] aad = createAAD(header);

            // the AEC-CCM and AES-GCM both will generate cipherText with authentication tag
            byte[] cipherTextWithMac;
            try {
                AEADBlockCipher aeadBlockCipher = securityProvider.getAEADBlockCipher(cipher.getAlgorithmName());
                aeadBlockCipher.init(Cipher.CryptMode.ENCRYPT, encryptionKey.getEncoded(), parameterSpec);
                aeadBlockCipher.updateAAD(aad, 0, aad.length);
                cipherTextWithMac = aeadBlockCipher.doFinal(plainText, 0, plainText.length);
            } catch (SecurityException e) {
                logger.error("Security exception while encrypting packet << {} >>", packet.getHeader());
                throw new SMBRuntimeException(e);
            }

            // the plainTextSize should equals cipherTextSize - AUTHENTICATION_TAG_LENGTH
            if (cipherTextWithMac.length != plainText.length + 16) {
                throw new IllegalStateException("Invalid length for cipherText after encryption.");
            }

            byte[] signature = new byte[16];
            System.arraycopy(cipherTextWithMac, plainText.length, signature, 0, signature.length);
            header.setSignature(signature);

            header.writeTo(buffer);
            buffer.putRawBytes(cipherTextWithMac, 0, plainText.length);
        }

        @Override
        public SMB2PacketHeader getHeader() {
            return packet.getHeader();
        }

        @Override
        public int getMaxPayloadSize() {
            return packet.getMaxPayloadSize();
        }

        @Override
        public long getSequenceNumber() {
            return packet.getSequenceNumber();
        }

        @Override
        public int getStructureSize() {
            return packet.getStructureSize();
        }

        @Override
        public String toString() {
            return "Encrypted[" + packet.toString() + "]";
        }

        /**
         * Return the result of the {@link #getPacket()} call on the wrapped packet.
         * @return The unwrapped wrapppedPacket
         */
        @Override
        public SMB2Packet getPacket() {
            return packet.getPacket();
        }

    }
}
