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
import com.hierynomus.smbj.common.SMBBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class PacketSignatory {
    private static final Logger logger = LoggerFactory.getLogger(PacketSignatory.class);

    public static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

    private static final byte[] EMPTY_SIGNATURE = new byte[SMB2Header.SIGNATURE_SIZE];
    static {
        Arrays.fill(EMPTY_SIGNATURE, (byte) 0);
    }

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
        try {
            Mac mac = getMac(secretKey);
            SMBBuffer buffer = packet.getBuffer();
            mac.update(buffer.array(), 0, SMB2Header.SIGNATURE_OFFSET); // TODO this won't work in compounding
            mac.update(EMPTY_SIGNATURE);
            mac.update(buffer.array(), SMB2Header.STRUCTURE_SIZE, buffer.available());
            byte[] signature = mac.doFinal();
            byte[] receivedSignature = Arrays.copyOfRange(buffer.array(), SMB2Header.SIGNATURE_OFFSET, SMB2Header.STRUCTURE_SIZE);
            return Arrays.equals(signature, receivedSignature);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Mac getMac(SecretKeySpec signingKeySpec) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(signingKeySpec.getAlgorithm());
        mac.init(signingKeySpec);
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
            try {
                wrappedPacket.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_SIGNED);
                int packetStartPos = buffer.wpos();
                SigningBuffer signingBuffer = new SigningBuffer(buffer, secretKey);
                // Write the real packet to the buffer
                wrappedPacket.write(signingBuffer);
                // The MAC in the signingbuffer now contains the right signature.
                byte[] signature = signingBuffer.mac.doFinal();
                // Copy the signature into the buffer's data at the right point.
                System.arraycopy(signature, 0, buffer.array(), packetStartPos + SMB2Header.SIGNATURE_OFFSET, SMB2Header.SIGNATURE_SIZE);
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                // TODO other exception
                throw new IllegalStateException(e);
            }
        }

        private class SigningBuffer extends SMBBuffer {
            private SMBBuffer wrappedBuffer;
            private final Mac mac;

            public SigningBuffer(SMBBuffer wrappedBuffer, SecretKeySpec signingKeySpec) throws NoSuchAlgorithmException, InvalidKeyException {
                this.wrappedBuffer = wrappedBuffer;
                mac = getMac(signingKeySpec);
            }

            @Override
            public Buffer<SMBBuffer> putByte(byte b) {
                mac.update(b);
                wrappedBuffer.putByte(b);
                return this;
            }

            @Override
            public Buffer<SMBBuffer> putBuffer(Buffer<? extends Buffer<?>> buffer) {
                mac.update(buffer.array(), buffer.rpos(), buffer.available());
                wrappedBuffer.putBuffer(buffer);
                return this;
            }

            @Override
            public Buffer<SMBBuffer> putRawBytes(byte[] buf, int offset, int length) {
                mac.update(buf, offset, length);
                wrappedBuffer.putRawBytes(buf, offset, length);
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
