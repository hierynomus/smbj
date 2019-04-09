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
package com.hierynomus.mssmb2;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.transport.PacketFactory;
import com.hierynomus.security.AEADBlockCipher;
import com.hierynomus.security.Cipher.CryptMode;
import com.hierynomus.security.DecryptPacketInfo;
import com.hierynomus.security.SecurityException;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.common.Check;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Key;

import javax.crypto.spec.GCMParameterSpec;

public class SMB3EncryptedPacketFactory implements PacketFactory<SMB2PacketData> {
    private static final Logger logger = LoggerFactory.getLogger(SMB3EncryptedPacketFactory.class);
    // 2.2.41 SMB2 TRANSFORM_HEADER -- ProtocolId (4 bytes)
    private static final byte[] SMB2_TRANSFORM_HEADER_PROTOCOL_ID = SMB2TransformHeaderFunctions.SMB2_TRANSFORM_HEADER_PROTOCOL_ID;
    // 2.2.41 SMB2 TRANSFORM_HEADER
    private static final int SMB2_TRANSFORM_HEADER_SIZE = SMB2TransformHeaderFunctions.SMB2_TRANSFORM_HEADER_SIZE;
    // 2.2.41 SMB2 TRANSFORM_HEADER - SessionId (8 bytes)
    private static final int SMB2_TRANSFORM_HEADER_SESSION_ID_OFFSET = SMB2TransformHeaderFunctions.SMB2_TRANSFORM_HEADER_SESSION_ID_OFFSET;

    private SMB2PacketFactory smb2PacketFactory;
    private SecurityProvider securityProvider;

    public SMB3EncryptedPacketFactory(SMB2PacketFactory smb2PacketFactory, SecurityProvider securityProvider) {
        this.smb2PacketFactory = smb2PacketFactory;
        this.securityProvider = securityProvider;
    }

    @Override
    public SMB2PacketData read(byte[] data) throws Buffer.BufferException {
        throw new IllegalStateException("Calling to SMB3EncryptedPacketFactory without providing decryptionInfo");
    }

    public SMB2PacketData read(byte[] data, DecryptPacketInfo decryptPacketInfo) throws Buffer.BufferException {
        return read(new SMBBuffer(data), decryptPacketInfo);
    }

    public long readSessionId(byte[] data) throws Buffer.BufferException {
        SMBBuffer buffer = new SMBBuffer(data);
        // Check we see a valid header start
        Check.ensureEquals(buffer.readRawBytes(4), SMB2_TRANSFORM_HEADER_PROTOCOL_ID, "Could not find SMB2_TRANSFORM_HEADER");
        buffer.skip(SMB2_TRANSFORM_HEADER_SESSION_ID_OFFSET - 4 ); // Skip until sessionId
        return buffer.readLong(); // SessionId (8 bytes)
    }

    @Override
    public boolean canHandle(byte[] data) {
        return data[0] == (byte) 0xFD && data[1] == 'S' && data[2] == 'M' && data[3] == 'B';
    }

    private SMB2PacketData read(SMBBuffer buffer, DecryptPacketInfo decryptPacketInfo) throws Buffer.BufferException {
        if (decryptPacketInfo == null) {
            logger.error("Unable to decrypt a packet without a decryptionKey");
            throw new IllegalStateException("Unable to decrypt a packet without a decryptionKey");
        }

        // 3.2.5.1.1 Decrypting the Message
        // If the size of the message received from the server is not greater than the size of SMB2
        // TRANSFORM_HEADER as specified in section 2.2.41, the client MUST discard the message.
        if (buffer.available() <= SMB2_TRANSFORM_HEADER_SIZE) {
            return new SMB2SafeIgnorePacketData();
        }

        // Check we see a valid header start
        Check.ensureEquals(buffer.readRawBytes(4), SMB2_TRANSFORM_HEADER_PROTOCOL_ID, "Could not find SMB2_TRANSFORM_HEADER");
        // read the remaining part of the SMB2_TRANSFORM_HEADER
        byte[] signature = buffer.readRawBytes(16); // Signature (16 bytes)
        byte[] nonceField = buffer.readRawBytes(16); // Nonce (16 bytes)
        long originalMessageSize = buffer.readUInt32(); // OriginalMessageSize (4 bytes)
        buffer.skip(2); // Reserved (2 bytes)
        int flagsOrEncryptionAlgorithm = buffer.readUInt16(); // Flags/EncryptionAlgorithm (2 bytes)
        long sessionId = buffer.readLong(); // SessionId (8 bytes)
        byte[] cipherText = buffer.readRawBytes((int) originalMessageSize); // encrypted packet (variable)

        // 3.2.5.1.1 Decrypting the Message
        // If the Flags/EncryptionAlgorithm in the SMB2 TRANSFORM_HEADER is not 0x0001,
        // the client MUST discard the message.
        if (flagsOrEncryptionAlgorithm != 1) {
            return new SMB2SafeIgnorePacketData();
        }

        // decryption part
        final Key decryptionKey = decryptPacketInfo.getDecryptionKey();
        final Smb2EncryptionCipher algorithm = decryptPacketInfo.getAlgorithm();

        final byte[] aad = SMB2TransformHeaderFunctions.newAAD(nonceField, (int) originalMessageSize, sessionId);
        // the nonce actually used in encryption
        final byte[] nonce = SMB2TransformHeaderFunctions.getActualNonce(algorithm, nonceField);
        final GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);

        final byte[] plainText;
        try {
            plainText = privateDecrypt(cipherText, algorithm, decryptionKey, aad, parameterSpec, signature);
        } catch (SecurityException e) {
            // TODO handle the exception properly
            logger.error("Unable to decrypt a packet on sessionId {}", sessionId);
            throw new IllegalStateException(e);
        }

        // decryption is done, parse the SMB2Packet by the Smb2MessageConverter then return it
        if (smb2PacketFactory.canHandle(plainText)) {
            SMB2PacketData packetData = smb2PacketFactory.read(plainText);
            // isFromDecrypt is always true in here as we just finished the decrypt.
            packetData.setFromDecrypt(true);
            return packetData;
        } else {
            // TODO handle the exception properly
            logger.error("Unable to get valid Smb2 Packet after decrypt a packet on sessionId {}", sessionId);
            throw new IllegalStateException("Unable to get valid Smb2 Packet after decrypt a packet on sessionId" + sessionId);
        }
    }

    private byte[] privateDecrypt(byte[] cipherText, Smb2EncryptionCipher algorithm, Key decryptionKey, byte[] aad, GCMParameterSpec parameterSpec, byte[] signature) throws SecurityException {
        byte[] plainText;
        try {
            AEADBlockCipher aeadBlockCipher = securityProvider.getAEADBlockCipher(algorithm.getAlgorithmName());
            aeadBlockCipher.init(CryptMode.DECRYPT, decryptionKey.getEncoded(), parameterSpec);
            aeadBlockCipher.updateAAD(aad, 0, aad.length);
            byte[] returnedBytes01 = aeadBlockCipher.update(cipherText, 0, cipherText.length);
            byte[] returnedBytes02 = aeadBlockCipher.doFinal(signature, 0 , signature.length);

            // Assuming returnedBytes02 will be never null or empty as only CCM and GCM are used.
            if (returnedBytes01 != null && returnedBytes01.length != 0) {
                plainText = new byte[returnedBytes01.length + returnedBytes02.length];
                System.arraycopy(returnedBytes01, 0, plainText, 0, returnedBytes01.length);
                System.arraycopy(returnedBytes02, 0, plainText, returnedBytes01.length, returnedBytes02.length);
            } else {
                plainText = returnedBytes02;
            }
        } catch (SecurityException e) {
            logger.error("Unable to decrypt message, error occur : ", e);
            throw e;
        }
        return plainText;
    }

}
