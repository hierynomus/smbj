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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import javax.crypto.spec.GCMParameterSpec;

import com.hierynomus.mssmb2.SMB2TransformHeader;
import com.hierynomus.mssmb2.SMB3EncryptionCipher;
import com.hierynomus.security.AEADBlockCipher;
import com.hierynomus.security.Cipher;
import com.hierynomus.security.bc.BCSecurityProvider;

public class PacketEncryptorTest {
    @Test
    public void shouldUseCorrectSmb2TransformHeaderProtocolId() {
        byte[] transformHeaderProtocolId = new byte[] { (byte) 0xFD, (byte) 0x53, (byte) 0x4D, (byte) 0x42 };
        assertArrayEquals(SMB2TransformHeader.ENCRYPTED_PROTOCOL_ID, transformHeaderProtocolId);
    }

    @Test
    public void shouldBeAbleToFormAAD() {
        byte[] expectedAAD = new byte[] {
            // Nonce (16 bytes)
            (byte) 0x01, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0,
            (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0,
            // OriginalMessageSize (4 bytes)
            (byte) 0x10, (byte) 0x0, (byte) 0x0, (byte) 0x0,
            // Reserved (2 bytes)
            (byte) 0x0, (byte) 0x0,
            // Flags/EncryptionAlgorithm (2 bytes)
            (byte) 0x01, (byte) 0x0,
            // SessionId (8 bytes)
            (byte) 0x01, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0
        };

        SMB2TransformHeader header = new SMB2TransformHeader(new byte[] { (byte) 0x01, (byte) 0x0, (byte) 0x0,
            (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0,
            (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0 }, 16, 1);

        byte[] aad = new PacketEncryptor(new BCSecurityProvider()).createAAD(header);

        assertArrayEquals(expectedAAD, aad);
    }

    @ParameterizedTest(name = "Encryptor with c)ipher {0} should generate correct nonce length")
    @EnumSource(value = SMB3EncryptionCipher.class)
    public void shouldGiveCorrectNonceLength(SMB3EncryptionCipher cipher) {
        PacketEncryptor pe = new PacketEncryptor(new BCSecurityProvider());
        pe.setCipher(cipher);
        assertEquals(cipher.getNonceLength(), pe.getNewNonce().length);
    }

    @ParameterizedTest(name = "Cipher {0} should encrypt and decrypt with a key of its key length")
    @EnumSource(value = SMB3EncryptionCipher.class)
    public void shouldRoundTripWithKeyLength(SMB3EncryptionCipher cipher) throws Exception {
        BCSecurityProvider securityProvider = new BCSecurityProvider();
        byte[] key = new byte[cipher.getKeyLength() / 8];
        byte[] nonce = new byte[cipher.getNonceLength()];
        byte[] aad = new byte[] { 1, 2, 3 };
        byte[] plainText = "SMB 3.1.1 encrypted payload".getBytes("UTF-8");

        AEADBlockCipher encryptor = securityProvider.getAEADBlockCipher(cipher.getAlgorithmName());
        encryptor.init(Cipher.CryptMode.ENCRYPT, key, new GCMParameterSpec(128, nonce));
        encryptor.updateAAD(aad, 0, aad.length);
        byte[] cipherTextWithMac = encryptor.doFinal(plainText, 0, plainText.length);
        assertEquals(plainText.length + 16, cipherTextWithMac.length);

        AEADBlockCipher decryptor = securityProvider.getAEADBlockCipher(cipher.getAlgorithmName());
        decryptor.init(Cipher.CryptMode.DECRYPT, key, new GCMParameterSpec(128, nonce));
        decryptor.updateAAD(aad, 0, aad.length);
        assertArrayEquals(plainText, decryptor.doFinal(cipherTextWithMac, 0, cipherTextWithMac.length));
    }
}
