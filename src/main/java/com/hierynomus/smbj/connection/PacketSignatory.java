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

import static com.hierynomus.mssmb2.SMB2MessageFlag.SMB2_FLAGS_SIGNED;
import static com.hierynomus.mssmb2.SMB2PacketHeader.EMPTY_SIGNATURE;
import static com.hierynomus.mssmb2.SMB2PacketHeader.SIGNATURE_OFFSET;
import static com.hierynomus.mssmb2.SMB2PacketHeader.SIGNATURE_SIZE;
import static com.hierynomus.mssmb2.SMB2PacketHeader.STRUCTURE_SIZE;

import java.util.Arrays;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.mssmb2.SMB2PacketHeader;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.security.Mac;
import com.hierynomus.security.SecurityException;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.smb.SMBBuffer;

public class PacketSignatory {
    private static final Logger logger = LoggerFactory.getLogger(PacketSignatory.class);

    private SecurityProvider securityProvider;

    PacketSignatory(SecurityProvider securityProvider) {
        this.securityProvider = securityProvider;
    }

    void init() {
    }

    public SMB2Packet sign(SMB2Packet packet, SecretKey secretKey) {
        if (secretKey != null) {
            return new SignedPacketWrapper(packet, secretKey);
        } else {
            logger.debug("Not wrapping {} as signed, as no key is set.", packet.getHeader().getMessage());
            return packet;
        }
    }

    // TODO make session a packet handler which wraps the incoming packets
    public boolean verify(SMB2PacketData packet, SecretKey secretKey) {
        try {
            SMBBuffer buffer = packet.getDataBuffer();
            Mac mac = getMac(secretKey, securityProvider);
            mac.update(buffer.array(), packet.getHeader().getHeaderStartPosition(), SIGNATURE_OFFSET);
            mac.update(EMPTY_SIGNATURE);
            mac.update(buffer.array(), STRUCTURE_SIZE, packet.getHeader().getMessageEndPosition() - STRUCTURE_SIZE);
            byte[] signature = mac.doFinal();
            byte[] receivedSignature = packet.getHeader().getSignature();
            for (int i = 0; i < SIGNATURE_SIZE; i++) {
                if (signature[i] != receivedSignature[i]) {
                    logger.error("Signatures for packet {} do not match (received: {}, calculated: {})", packet,
                            Arrays.toString(receivedSignature), Arrays.toString(signature));
                    logger.error("Packet {} has header: {}", packet, packet.getHeader());
                    return false;
                }
            }

            return true;
        } catch (SecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Mac getMac(SecretKey secretKey, SecurityProvider securityProvider) throws SecurityException {
        Mac mac = securityProvider.getMac(secretKey.getAlgorithm());
        mac.init(secretKey.getEncoded());
        return mac;
    }

    public class SignedPacketWrapper extends SMB2Packet {
        private final SMB2Packet wrappedPacket;
        private SecretKey secretKey;

        SignedPacketWrapper(SMB2Packet packet, SecretKey secretKey) {
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
            private final Mac mac;

            SigningBuffer(SMBBuffer wrappedBuffer) throws SecurityException {
                this.wrappedBuffer = wrappedBuffer;
                mac = getMac(secretKey, PacketSignatory.this.securityProvider);
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
        public SMB2PacketHeader getHeader() {
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
            return "Signed(" + wrappedPacket.toString() + ")";
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
