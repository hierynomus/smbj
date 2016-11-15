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
import com.hierynomus.mssmb2.SMB2MessageFlag;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.RawOutputBuffer;
import com.hierynomus.protocol.commons.buffer.RawTeeOutputBuffer;
import com.hierynomus.smbj.common.SMBBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static com.hierynomus.mssmb2.SMB2Header.EMPTY_SIGNATURE;
import static com.hierynomus.mssmb2.SMB2Header.SIGNATURE_SIZE;

public class PacketSignatory {
    private static final Logger logger = LoggerFactory.getLogger(PacketSignatory.class);

    public static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

    private SMB2Dialect dialect;
    private SecretKeySpec secretKey;

    public PacketSignatory(SMB2Dialect dialect) {
        this.dialect = dialect;
    }

    void init(byte[] secretKey) {
        if (dialect.isSmb3x()) {
            throw new IllegalStateException("Cannot set a signing key (yet) for SMB3.x");
        } else {
            this.secretKey = new SecretKeySpec(secretKey, HMAC_SHA256_ALGORITHM);
        }
    }

    boolean isInitialized() {
        return secretKey != null;
    }

    SMB2Packet sign(SMB2Packet packet) {
        if (secretKey != null) {
            return new SignedPacketWrapper(packet, secretKey);
        } else {
            logger.debug("Not wrapping {} as signed, as no key is set.", packet.getHeader().getMessage());
            return packet;
        }
    }

    // TODO make session a packet handler which wraps the incoming packets
    public boolean verify(SMB2Packet packet) {
        SMBBuffer buffer = packet.getBuffer();
        Mac mac = getMac(secretKey);
        mac.update(buffer.array(), packet.getMessageStartPos(), SMB2Header.SIGNATURE_OFFSET);
        mac.update(EMPTY_SIGNATURE);
        mac.update(buffer.array(), SMB2Header.STRUCTURE_SIZE, packet.getMessageEndPos() - SMB2Header.STRUCTURE_SIZE);
        byte[] signature = mac.doFinal();
        byte[] receivedSignature = Arrays.copyOfRange(buffer.array(), SMB2Header.SIGNATURE_OFFSET, SMB2Header.STRUCTURE_SIZE);
        for (int i = 0; i < SIGNATURE_SIZE; i++) {
            if (signature[i] != receivedSignature[i]) {
                return false;
            }
        }

        return true;
    }

    private static Mac getMac(SecretKeySpec signingKeySpec) {
        Mac mac = null;
        try {
            mac = Mac.getInstance(signingKeySpec.getAlgorithm());
            mac.init(signingKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            // TODO other exception
            throw new IllegalStateException(e);
        }

        return mac;
    }

    public static class SignedPacketWrapper extends SMB2Packet {
        private final SMB2Packet wrappedPacket;
        private final SecretKeySpec secretKey;

        SignedPacketWrapper(SMB2Packet packet, SecretKeySpec secretKey) {
            this.wrappedPacket = packet;
            this.secretKey = secretKey;
        }

        @Override
        public int getMaxPayloadSize() {
            return wrappedPacket.getMaxPayloadSize();
        }

        @Override
        public void write(SMBBuffer buffer) {
            wrappedPacket.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_SIGNED);
            int packetStartPos = buffer.wpos();
            SigningBuffer signingBuffer = new SigningBuffer(secretKey);
            new SMBBuffer(new RawTeeOutputBuffer(buffer, signingBuffer));
            // Write the real packet to the buffer
            wrappedPacket.write(signingBuffer);
            // The MAC in the signingbuffer now contains the right signature.
            byte[] signature = signingBuffer.mac.doFinal();
            // Copy the signature into the buffer's data at the right point.
            System.arraycopy(signature, 0, buffer.array(), packetStartPos + SMB2Header.SIGNATURE_OFFSET, SMB2Header.SIGNATURE_SIZE);
        }

        private class SigningBuffer implements RawOutputBuffer<SigningBuffer> {
            private final Mac mac;
            private SecretKeySpec signingKeySpec;

            public SigningBuffer(SecretKeySpec signingKeySpec) {
                mac = getMac(signingKeySpec);
                this.signingKeySpec = signingKeySpec;
            }

            @Override
            public int wpos() {
                throw new IllegalStateException("wpos");
            }

            @Override
            public void clear() {
                mac.reset();
                try {
                    mac.init(signingKeySpec);
                } catch (InvalidKeyException e) {
                    throw new IllegalStateException(e);
                }
            }

            @Override
            public RawOutputBuffer<SigningBuffer> putByte(byte b) {
                mac.update(b);
                return this;
            }

            @Override
            public RawOutputBuffer<SigningBuffer> putRawBytes(byte[] buf) {
                mac.update(buf);
                return this;
            }

            @Override
            public RawOutputBuffer<SigningBuffer> putRawBytes(byte[] buf, int offset, int length) {
                mac.update(buf, offset, length);
                return this;
            }

        }

        @Override
        public SMB2Header getHeader() {
            return wrappedPacket.getHeader();
        }

        @Override
        public long getSequenceNumber() {
            return wrappedPacket.getSequenceNumber();
        }

        @Override
        public int getStructureSize() {
            return wrappedPacket.getStructureSize();
        }
    }
}
