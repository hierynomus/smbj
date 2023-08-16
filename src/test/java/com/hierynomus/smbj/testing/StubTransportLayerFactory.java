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
package com.hierynomus.smbj.testing;

import java.io.IOException;
import java.net.InetSocketAddress;

import com.hierynomus.mssmb2.SMB2MessageConverter;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.mssmb2.SMB2PacketHeader;
import com.hierynomus.protocol.Packet;
import com.hierynomus.protocol.PacketData;
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.protocol.transport.PacketHandlers;
import com.hierynomus.protocol.transport.PacketReceiver;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.transport.TransportLayerFactory;

public class StubTransportLayerFactory<D extends PacketData<?>, P extends Packet<?>>
        implements TransportLayerFactory<D, P> {
    private PacketProcessor processor;

    public StubTransportLayerFactory(PacketProcessor p) {
        this.processor = p;
    }

    @Override
    public TransportLayer<P> createTransportLayer(PacketHandlers<D, P> handlers,
            SmbConfig config) {
        return new StubTransportLayer<>(handlers.getReceiver(), processor);
    }

    private static class StubTransportLayer<D extends PacketData<?>, P extends Packet<?>> implements TransportLayer<P> {
        private boolean connected;
        private PacketReceiver<D> receiver;
        private PacketProcessor processPacket;

        StubTransportLayer(PacketReceiver<D> receiver, PacketProcessor processPacket) {
            this.receiver = receiver;
            if (this.receiver instanceof Connection) {
                ((Connection) this.receiver).setMessageConverter(new StubMessageConverter());
            }

            this.processPacket = processPacket;
        }

        @Override
        public void write(P packet) throws TransportException {
            if (!(packet instanceof SMB2Packet)) {
                throw new TransportException("Unsupported packet type " + packet.getClass().getSimpleName());
            }
            SMB2Packet request = (SMB2Packet) packet;
            SMB2Packet response = processPacket.process(request);

            if (response != null) {
                response.getHeader().setMessageId(request.getHeader().getMessageId());
                response.getHeader().setCreditResponse(request.getHeader().getCreditRequest());
                try {
                    receiver.handle((D) new StubPacketData(response));
                } catch (BufferException e) {
                    throw new TransportException(e);
                }
            } else {
                throw new TransportException("No response for " + packet);
            }
        }

        @Override
        public void connect(InetSocketAddress remoteAddress) throws IOException {
            connected = true;
        }

        @Override
        public void disconnect() throws IOException {
            connected = false;
        }

        @Override
        public boolean isConnected() {
            return connected;
        }
    }

    private static class StubPacketData extends SMB2PacketData {
        private SMB2Packet packet;

        StubPacketData(SMB2Packet packet) throws BufferException {
            super(new byte[0]);
            this.packet = packet;
        }

        @Override
        public SMB2PacketHeader getHeader() {
            return packet.getHeader();
        }

        @Override
        protected void readHeader() throws BufferException {
        }
    }

    private static class StubMessageConverter extends SMB2MessageConverter {
        private SMB2MessageConverter realConverter = new SMB2MessageConverter();

        @Override
        public SMB2Packet readPacket(SMBPacket requestPacket, SMB2PacketData packetData) throws BufferException {
            if (packetData instanceof StubPacketData) {
                return ((StubPacketData) packetData).packet;
            } else {
                return realConverter.readPacket(requestPacket, packetData);
            }
        }
    }
}
