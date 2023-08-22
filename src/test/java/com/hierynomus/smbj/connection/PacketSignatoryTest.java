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

import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.protocol.commons.ByteArrayUtils;
import com.hierynomus.security.bc.BCSecurityProvider;

public class PacketSignatoryTest {
    private SecretKey signingKey = new SecretKeySpec(
            new byte[] { (byte) 0x75, (byte) 0xc5, (byte) 0xcb, (byte) 0x91, (byte) 0x41, (byte) 0x9e, (byte) 0x3a,
                (byte) 0x45, (byte) 0xce, (byte) 0x9e,
                (byte) 0xf8, (byte) 0x69, (byte) 0xdf, (byte) 0xd3, (byte) 0xe2, (byte) 0xa8 },
            SMBSessionBuilder.HMAC_SHA256_ALGORITHM);
    private PacketSignatory signatory = new PacketSignatory(new BCSecurityProvider());

    @Test
    public void shouldVerifySignatureOfNonSuccessPacket() throws Exception {
        SMB2PacketData packet = new SMB2PacketData(new byte[] { (byte) 0xfe, (byte) 0x53, (byte) 0x4d, (byte) 0x42,
            (byte) 0x40, (byte) 0x00, (byte) 0x10, (byte) 0x00, (byte) 0x06, (byte) 0x00, (byte) 0x00, (byte) 0x80,
            (byte) 0x0e, (byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x09, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x15, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x25, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x24, (byte) 0x00, (byte) 0x00, (byte) 0x46, (byte) 0xef, (byte) 0xdd, (byte) 0x50,
            (byte) 0xd6, (byte) 0xcd, (byte) 0xaa, (byte) 0x25, (byte) 0xba, (byte) 0xc7, (byte) 0xc4, (byte) 0xb5,
            (byte) 0xd4, (byte) 0x9a, (byte) 0x0e, (byte) 0x08, (byte) 0x09, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x05 });

        assertTrue(signatory.verify(packet, signingKey));
    }

    @Test
    public void shouldVerifySignatureOfPaddedPacket() throws Exception {
        SMB2PacketData packet = new SMB2PacketData(ByteArrayUtils.parseHex(
            "fe534d4240000100030100c0050001000900000000000000ba9e62000000000000000000010000009103001c041400001FEDE330C927BC01F83C3C0E07DCB0BA09000000000000000000000000000000"));

        assertTrue(signatory.verify(packet, signingKey));
    }

}
