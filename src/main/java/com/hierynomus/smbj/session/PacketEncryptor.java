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
package com.hierynomus.smbj.session;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2Header;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2TransformHeaderFunctions;
import com.hierynomus.mssmb2.Smb2EncryptionCipher;
import com.hierynomus.security.AEADBlockCipher;
import com.hierynomus.security.Cipher.CryptMode;
import com.hierynomus.security.CryptographicKeysGenerator;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.security.SecurityException;
import com.hierynomus.smb.SMBBuffer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.Key;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class PacketEncryptor {
    private static final Logger logger = LoggerFactory.getLogger(PacketEncryptor.class);

    // 2.2.41 SMB2 TRANSFORM_HEADER -- ProtocolId (4 bytes)
    private static final byte[] SMB2_TRANSFORM_HEADER_PROTOCOL_ID = SMB2TransformHeaderFunctions.SMB2_TRANSFORM_HEADER_PROTOCOL_ID;
    // RFC 5116  section 5.1 and 5.3, https://tools.ietf.org/html/rfc5116#section-5.1
    private static final int AUTHENTICATION_TAG_LENGTH = SMB2TransformHeaderFunctions.AUTHENTICATION_TAG_LENGTH; // authentication tag with a length of 16 octets (128bits) is used
    // 2.2.41 SMB2 TRANSFORM_HEADER -- Nonce (16 bytes)
    private static final int AES128CCM_NONCE_LENGTH = SMB2TransformHeaderFunctions.AES128CCM_NONCE_LENGTH;
    private static final int AES128GCM_NONCE_LENGTH = SMB2TransformHeaderFunctions.AES128GCM_NONCE_LENGTH;

    private SMB2Dialect dialect;
    private final Smb2EncryptionCipher algorithm;
    private SecurityProvider securityProvider;
    private Key sessionKey = null;
    private Key encryptionKey = null;
    private Key decryptionKey = null;
    private BigInteger nonceCounter = BigInteger.ZERO;

    PacketEncryptor(SMB2Dialect dialect, SecurityProvider securityProvider, Smb2EncryptionCipher algorithm) {
        this.dialect = dialect;
        this.securityProvider = securityProvider;
        this.algorithm = algorithm;
    }

    void init(byte[] sessionKey) {
        init(sessionKey, null);
    }

    void init(byte[] sessionKey, byte[] sessionPreauthIntegrityHashValue) {
        if (dialect.isSmb3x()) {
            if (algorithm == null) {
                throw new IllegalStateException("Encryption algorithm is null when initializing PacketEncryptor");
            }
            if (sessionKey != null) {
                this.sessionKey = new SecretKeySpec(sessionKey, "");
                if (dialect == SMB2Dialect.SMB_3_1_1) {
                    if (sessionPreauthIntegrityHashValue == null) {
                        // dialect 3.1.1 with null for sessionPreauthIntegrityHashValue case,

                        logger.error("sessionPreauthIntegrityHashValue is null when generating encryption key for SMB3.1.1");
                        throw new IllegalStateException("sessionPreauthIntegrityHashValue is null when generating encryption key for SMB3.1.1");
                    }

                    // dialect 3.1.1 with non-null value for sessionPreauthIntegrityHashValue case,

                    this.encryptionKey = CryptographicKeysGenerator.generateKey(
                        this.sessionKey,
                        CryptographicKeysGenerator.Smb311EncryptLabelByteArray,
                        sessionPreauthIntegrityHashValue,
                        algorithm.getAlgorithmName()
                    );
                    this.decryptionKey = CryptographicKeysGenerator.generateKey(
                        this.sessionKey,
                        CryptographicKeysGenerator.Smb311DecryptLabelByteArray,
                        sessionPreauthIntegrityHashValue,
                        algorithm.getAlgorithmName()
                    );
                } else {
                    // remaining dialect 3.0.x case,

                    this.encryptionKey = CryptographicKeysGenerator.generateKey(
                        this.sessionKey,
                        CryptographicKeysGenerator.Smb30xEncryptLabelByteArray,
                        CryptographicKeysGenerator.Smb30xEncryptContextByteArray,
                        algorithm.getAlgorithmName()
                    );
                    this.decryptionKey = CryptographicKeysGenerator.generateKey(
                        this.sessionKey,
                        CryptographicKeysGenerator.Smb30xDecryptLabelByteArray,
                        CryptographicKeysGenerator.Smb30xDecryptContextByteArray,
                        algorithm.getAlgorithmName()
                    );
                }
            } else {
                // TODO throw Error?
                this.sessionKey = null;
                this.encryptionKey = null;
                this.decryptionKey = null;
            }
        } else {
            throw new IllegalStateException("Encryption is not supported for SMB2.x family");
        }
    }

    boolean isInitialized() {
        return sessionKey != null && encryptionKey != null && decryptionKey != null;
    }

    SMB2Packet encrypt(SMB2Packet packet) {
        if (isInitialized()) {
            return new EncryptedPacketWrapper(packet);
        } else {
            logger.debug("Not wrapping {} as encrypted, as no key is set.", packet.getHeader().getMessage());
            return packet;
        }
    }

    private byte[] getNewNonceField() {
        byte[] nonce; // Nonce is always 16 bytes in SMB2_TRANSFORM_HEADER
        byte[] nonceCounterArray = nonceCounter.toByteArray();
        // increment the nonceCounter
        nonceCounter = nonceCounter.add(BigInteger.ONE);

        // Base on the selected algorithm, generate the nonce.
        switch (algorithm) {
            case AES_128_CCM: {
                nonce = privateStaticGetNonce(nonceCounterArray, AES128CCM_NONCE_LENGTH);
                break;
            }
            case AES_128_GCM: {
                nonce = privateStaticGetNonce(nonceCounterArray, AES128GCM_NONCE_LENGTH);
                break;
            }
            default:
                throw new IllegalStateException("Unknown encryption algorithm (not supported) when generating new nonce.");
        }

        return nonce;
    }

    private static byte[] privateStaticGetNonce(byte[] nonceCounterArray, final int nonceLength) {
        SMBBuffer buffer = new SMBBuffer();
        if (nonceCounterArray.length < nonceLength) {
            int addingZeros = nonceLength - nonceCounterArray.length;
            // since nonceCounterArray.length < nonceLength, it will be fine.
            // Using the less significant bit first.
            for (int i = 0; i < nonceCounterArray.length; i++) {
                int index = nonceCounterArray.length - 1 - i;
                buffer.putByte(nonceCounterArray[index]);
            }
            buffer.putReserved(addingZeros);
        } else {
            // Using the less significant bit first.
            for (int i = 0; i < nonceLength; i++) {
                int index = nonceCounterArray.length - 1 - i;
                buffer.putByte(nonceCounterArray[index]);
            }
        }
        // Reserved (4 bytes for AES128CCM, 5 bytes for AES128GCM)
        buffer.putReserved(16 - nonceLength);

        return buffer.getCompactData();
    }

    private byte[] privateEncrypt(byte[] plainText, byte[] aad, GCMParameterSpec parameterSpec)
        throws SecurityException {
        byte[] cipherText;
        try {
            AEADBlockCipher aeadBlockCipher = securityProvider.getAEADBlockCipher(algorithm.getAlgorithmName());
            aeadBlockCipher.init(CryptMode.ENCRYPT, encryptionKey.getEncoded(), parameterSpec);
            aeadBlockCipher.updateAAD(aad, 0, aad.length);
            cipherText = aeadBlockCipher.doFinal(plainText, 0, plainText.length);
        } catch (SecurityException e) {
            logger.error("Unable to encrypt message, error occur : ", e);
            throw e;
        }
        return cipherText;
    }

    public class EncryptedPacketWrapper extends SMB2Packet {
        private final SMB2Packet wrappedPacket;

        EncryptedPacketWrapper(SMB2Packet packet) {
            this.wrappedPacket = packet;
        }

        @Override
        public int getMaxPayloadSize() {
            return wrappedPacket.getMaxPayloadSize();
        }

        @Override
        public void write(SMBBuffer buffer) {
            // 3.2.4.1.1 Signing the Message,
            // If the client encrypts the message, as specified in section 3.1.4.3,
            // then the client MUST set the Signature field of the SMB2 header to zero.
            // Checked with Windows 10 Client behaviour, should NOT set SMB2_FLAGS_SIGNED as well.

            SMBBuffer plainTextBuffer = new SMBBuffer();
            // Write the whole plainText packet to the buffer
            wrappedPacket.write(plainTextBuffer);
            // number of bytes available to read is equals to packet size
            final int plainTextSize = plainTextBuffer.available();
            final byte[] plainText = plainTextBuffer.getCompactData();

            if (plainText.length != plainTextSize) {
                // TODO throw exception?
                logger.debug("plainText.length != plainTextSize");
            }

            // The nonce used in the SMB2_TRANSFORM_HEADER
            final byte[] nonceField = getNewNonceField();
            // the nonce actually used in encryption
            final byte[] nonce = SMB2TransformHeaderFunctions.getActualNonce(algorithm, nonceField);
            final GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);

            // 3.1.4.3 Encrypting the Message, The SMB2 TRANSFORM_HEADER,
            // excluding the ProtocolId and Signature fields,
            // as the optional authenticated data.
            final byte[] aad = SMB2TransformHeaderFunctions.newAAD(nonceField, plainTextSize, wrappedPacket.getHeader().getSessionId());

            // the AEC-CCM and AES-GCM both will generate cipherText with authentication tag
            byte[] cipherTextWithMac;
            try {
                cipherTextWithMac = privateEncrypt(plainText, aad, parameterSpec);
            } catch (SecurityException e) {
                // TODO Handle the exception properly
                throw new IllegalStateException(e);
            }
            // the plainTextSize should equals cipherTextSize - AUTHENTICATION_TAG_LENGTH
            if (cipherTextWithMac.length != plainTextSize + AUTHENTICATION_TAG_LENGTH) {
                throw new IllegalStateException("Invalid length for cipherText after encryption.");
            }

            // Actual Writing the Packet with SMB2_TRANSFORM_HEADER
            buffer.putRawBytes(SMB2_TRANSFORM_HEADER_PROTOCOL_ID); // ProtocolId (4 bytes)
            buffer.putRawBytes(cipherTextWithMac, plainTextSize, AUTHENTICATION_TAG_LENGTH); // Signature (16 bytes)
            buffer.putRawBytes(aad); // Nonce (16 bytes), OriginalMessageSize (4 bytes), Reserved (2 bytes), Flags/EncryptionAlgorithm (2 bytes), SessionId (8 bytes)
            buffer.putRawBytes(cipherTextWithMac, 0, plainTextSize); // encrypted packet (variable)
        }

        @Override
        public SMB2Header getHeader() {
            return wrappedPacket.getHeader();
        }

        // TODO do we need to override this function?
        @Override
        public long getSequenceNumber() {
            return wrappedPacket.getSequenceNumber();
        }

        // TODO do we need to override this function?
        @Override
        public int getStructureSize() {
            return wrappedPacket.getStructureSize();
        }

        @Override
        public String toString() {
            return wrappedPacket.toString();
        }

        /**
         * Return the result of the {@link #getPacket()} call on the wrapped packet.
         * @return The unwrapped wrapppedPacket
         */
        @Override
        public SMB2Packet getPacket() {
            return wrappedPacket.getPacket();
        }
    }
}
