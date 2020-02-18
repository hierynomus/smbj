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

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB3EncryptedPacketData;
import com.hierynomus.mssmb2.SMB3EncryptionCipher;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.security.AEADBlockCipher;
import com.hierynomus.security.Cipher;
import com.hierynomus.security.SecurityException;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.common.SMBRuntimeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.spec.GCMParameterSpec;
import java.util.Arrays;

public class PacketEncryptor {
    private static final Logger logger = LoggerFactory.getLogger(PacketEncryptor.class);
    private SecurityProvider securityProvider;
    private SMB3EncryptionCipher cipher;

    public PacketEncryptor(SecurityProvider securityProvider) {
        this.securityProvider = securityProvider;
    }

    void init(ConnectionInfo connectionInfo) {
        // The client MUST decrypt the message using Session.DecryptionKey. If Connection.Dialect is "3.1.1", the algorithm
        // specified by Connection.CipherId is used. Otherwise, the AES-128-CCM algorithm is used.
        if (connectionInfo.getNegotiatedProtocol().getDialect().equals(SMB2Dialect.SMB_3_1_1)) {
            cipher = connectionInfo.getCipherId();
        } else {
            cipher = SMB3EncryptionCipher.AES_128_CCM;
        }
    }

    public byte[] decrypt(SMB3EncryptedPacketData packetData, byte[] encryptionKey) {
        byte[] realNonce = Arrays.copyOf(packetData.getHeader().getNonce(), cipher.getNonceLength());
        try {
            byte[] aad = createAAD(packetData);
            byte[] cipherText = packetData.getCipherText();
            byte[] signature = packetData.getHeader().getSignature();

            AEADBlockCipher aeadBlockCipher = securityProvider.getAEADBlockCipher(cipher.getAlgorithmName());
            aeadBlockCipher.init(Cipher.CryptMode.DECRYPT, encryptionKey, new GCMParameterSpec(128, realNonce));
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

    private byte[] createAAD(SMB3EncryptedPacketData packetData) {
        SMBBuffer b = new SMBBuffer();
        packetData.getHeader().writeTo(b); // Write the header
        b.rpos(20); // Skip ProtocolId (4 bytes) AND Signature (16 bytes)
        return b.getCompactData();
    }

}
