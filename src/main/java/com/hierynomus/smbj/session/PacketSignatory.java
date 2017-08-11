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
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.security.SecurityException;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.smb.SMBBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

import static com.hierynomus.mssmb2.SMB2Header.*;
import static com.hierynomus.mssmb2.SMB2MessageFlag.SMB2_FLAGS_SIGNED;

public class PacketSignatory {
    private static final Logger logger = LoggerFactory.getLogger(PacketSignatory.class);

    private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

    private SMB2Dialect dialect;
    private SecurityProvider securityProvider;
    private String algorithm;
    private byte[] secretKey;

    PacketSignatory(SMB2Dialect dialect, SecurityProvider securityProvider) {
        this.dialect = dialect;
        this.securityProvider = securityProvider;
    }

    void init(byte[] secretKey) {
        if (dialect.isSmb3x()) {
            throw new IllegalStateException("Cannot set a signing key (yet) for SMB3.x");
        } else {
            algorithm = HMAC_SHA256_ALGORITHM;
            this.secretKey = secretKey;
        }
    }

    boolean isInitialized() {
        return secretKey != null;
    }

    SMB2Packet sign(SMB2Packet packet) {
        if (secretKey != null) {
            return new SignedPacketWrapper(packet);
        } else {
            logger.debug("Not wrapping {} as signed, as no key is set.", packet.getHeader().getMessage());
            return packet;
        }
    }

    // TODO make session a packet handler which wraps the incoming packets
    public boolean verify(SMB2Packet packet) {
        try {
            SMBBuffer buffer = packet.getBuffer();
            com.hierynomus.security.Mac mac = getMac(secretKey, algorithm, securityProvider);
            mac.update(buffer.array(), packet.getMessageStartPos(), SIGNATURE_OFFSET);
            mac.update(EMPTY_SIGNATURE);
            mac.update(buffer.array(), STRUCTURE_SIZE, packet.getMessageEndPos() - STRUCTURE_SIZE);
            byte[] signature = mac.doFinal();
            byte[] receivedSignature = packet.getHeader().getSignature();
            for (int i = 0; i < SIGNATURE_SIZE; i++) {
                if (signature[i] != receivedSignature[i]) {
                    logger.error("Signatures for packet {} do not match (received: {}, calculated: {})", packet, Arrays.toString(receivedSignature), Arrays.toString(signature));
                    return false;
                }
            }

            return true;
        } catch (SecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static com.hierynomus.security.Mac getMac(byte[] secretKey, String algorithm, SecurityProvider securityProvider) throws SecurityException {
        com.hierynomus.security.Mac mac = securityProvider.getMac(algorithm);
        mac.init(secretKey);
        return mac;
    }

    public class SignedPacketWrapper extends SMB2Packet {
        private final SMB2Packet wrappedPacket;

        SignedPacketWrapper(SMB2Packet packet) {
            this.wrappedPacket = packet;
        }

        @Override
        public int getMaxPayloadSize() {
            return wrappedPacket.getMaxPayloadSize();
        }

        @Override
        public void write(SMBBuffer buffer) {
            try {
                wrappedPacket.getHeader().setFlag(SMB2_FLAGS_SIGNED);
                int packetStartPos = buffer.wpos();
                SigningBuffer signingBuffer = new SigningBuffer(buffer);
                // Write the real packet to the buffer
                wrappedPacket.write(signingBuffer);
                // The MAC in the signingbuffer now contains the right signature.
                byte[] signature = signingBuffer.mac.doFinal();
                // Copy the signature into the buffer's data at the right point.
                System.arraycopy(signature, 0, buffer.array(), packetStartPos + SIGNATURE_OFFSET, SIGNATURE_SIZE);
            } catch (SecurityException e) {
                // TODO other exception
                throw new IllegalStateException(e);
            }
        }

        private class SigningBuffer extends SMBBuffer {
            private SMBBuffer wrappedBuffer;
            private final com.hierynomus.security.Mac mac;

            SigningBuffer(SMBBuffer wrappedBuffer) throws SecurityException {
                this.wrappedBuffer = wrappedBuffer;
                mac = getMac(PacketSignatory.this.secretKey, PacketSignatory.this.algorithm, PacketSignatory.this.securityProvider);
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

        @Override
        public String toString() {
            return wrappedPacket.toString();
        }
    }
}
