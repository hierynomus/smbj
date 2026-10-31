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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2TransformHeader;
import com.hierynomus.mssmb2.SMB3EncryptedPacketData;
import com.hierynomus.mssmb2.SMB3EncryptionCipher;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smb.SMBBuffer;

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

    @ParameterizedTest
    @EnumSource(SMB3EncryptionCipher.class)
    public void shouldGenerateUniqueNonces(SMB3EncryptionCipher cipher) {
        PacketEncryptor pe = new PacketEncryptor(new BCSecurityProvider());
        pe.setCipher(cipher);
        Set<ByteBuffer> nonces = new HashSet<>();
        byte[] previous = null;

        for (int i = 0; i < 100_000; i++) {
            byte[] nonce = pe.getNewNonce();
            assertEquals(cipher.getNonceLength(), nonce.length);
            assertTrue(nonces.add(ByteBuffer.wrap(nonce)), "Duplicate nonce");
            if (previous != null) {
                long previousCounter = ByteBuffer.wrap(previous).order(ByteOrder.LITTLE_ENDIAN).getLong();
                assertEquals(previousCounter + 1, ByteBuffer.wrap(nonce).order(ByteOrder.LITTLE_ENDIAN).getLong());
                assertArrayEquals(Arrays.copyOfRange(previous, 8, previous.length), Arrays.copyOfRange(nonce, 8, nonce.length));
            }
            previous = nonce;
        }
        assertEquals(100_000, nonces.size());
    }

    @ParameterizedTest
    @EnumSource(SMB3EncryptionCipher.class)
    public void shouldGenerateUniqueNoncesConcurrently(SMB3EncryptionCipher cipher) throws Exception {
        PacketEncryptor pe = new PacketEncryptor(new BCSecurityProvider());
        pe.setCipher(cipher);
        Set<ByteBuffer> nonces = ConcurrentHashMap.newKeySet();
        ExecutorService executor = Executors.newFixedThreadPool(4);
        CountDownLatch ready = new CountDownLatch(4);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();

        try {
            for (int i = 0; i < 4; i++) {
                futures.add(executor.submit(() -> {
                    ready.countDown();
                    assertTrue(start.await(5, TimeUnit.SECONDS));
                    for (int j = 0; j < 25_000; j++) {
                        byte[] nonce = pe.getNewNonce();
                        assertEquals(cipher.getNonceLength(), nonce.length);
                        assertTrue(nonces.add(ByteBuffer.wrap(nonce)), "Duplicate nonce");
                    }
                    return null;
                }));
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            for (Future<?> future : futures) {
                future.get(10, TimeUnit.SECONDS);
            }
            assertEquals(100_000, nonces.size());
        } finally {
            start.countDown();
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @ParameterizedTest
    @EnumSource(SMB3EncryptionCipher.class)
    public void shouldRejectNoncesAfterCounterExhaustion(SMB3EncryptionCipher cipher) throws Exception {
        PacketEncryptor pe = new PacketEncryptor(new BCSecurityProvider());
        pe.setCipher(cipher);
        Field limitField = PacketEncryptor.class.getDeclaredField("nonceCounterLimit");
        limitField.setAccessible(true);
        long limit = limitField.getLong(pe);
        Field counterField = PacketEncryptor.class.getDeclaredField("nonceCounter");
        counterField.setAccessible(true);
        ((AtomicLong) counterField.get(pe)).set(limit - 1);

        byte[] nonce = pe.getNewNonce();

        assertEquals(limit - 1, ByteBuffer.wrap(nonce).order(ByteOrder.LITTLE_ENDIAN).getLong());
        assertThrows(IllegalStateException.class, pe::getNewNonce);
        assertThrows(IllegalStateException.class, pe::getNewNonce);
    }

    @ParameterizedTest
    @EnumSource(SMB3EncryptionCipher.class)
    public void shouldEncryptAndDecryptForEachCipher(SMB3EncryptionCipher cipher) throws Exception {
        PacketEncryptor pe = new PacketEncryptor(new BCSecurityProvider());
        pe.setCipher(cipher);
        SecretKey key = new SecretKeySpec(new byte[16], "AES");
        SMB2Echo packet = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        packet.getHeader().setSessionId(1);
        packet.getHeader().setMessageId(42);
        SMBBuffer plainText = new SMBBuffer();
        packet.write(plainText);
        SMBBuffer encrypted = new SMBBuffer();

        pe.encrypt(packet, key).write(encrypted);
        byte[] decrypted = pe.decrypt(new SMB3EncryptedPacketData(encrypted.getCompactData()), key);

        assertArrayEquals(plainText.getCompactData(), decrypted);
    }
}
