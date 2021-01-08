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
package com.hierynomus.smbj.connection

import com.hierynomus.mssmb2.SMB2PacketHeader
import com.hierynomus.mssmb2.SMB2MessageConverter
import com.hierynomus.mssmb2.SMB2Packet
import com.hierynomus.mssmb2.SMB2PacketData
import com.hierynomus.protocol.commons.buffer.Buffer
import com.hierynomus.protocol.transport.PacketHandlers
import com.hierynomus.protocol.transport.PacketReceiver
import com.hierynomus.protocol.transport.TransportException
import com.hierynomus.protocol.transport.TransportLayer
import com.hierynomus.smb.SMBPacket
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.transport.TransportLayerFactory

class StubTransportLayerFactory implements TransportLayerFactory<SMB2PacketData, SMB2Packet> {
  private Closure<SMB2Packet> processPacket

  StubTransportLayerFactory(Closure<SMB2Packet> processPacket) {
    this.processPacket = processPacket
  }

  @Override
  TransportLayer<SMB2Packet> createTransportLayer(PacketHandlers<SMB2PacketData, SMB2Packet> handlers, SmbConfig config) {
    return new StubTransportLayer(handlers.receiver, processPacket)
  }

  private static class StubTransportLayer implements TransportLayer<SMB2Packet> {
    private boolean connected
    private PacketReceiver<SMB2PacketData> receiver
    private Closure<SMB2Packet> processPacket

    StubTransportLayer(PacketReceiver<SMB2PacketData> receiver, Closure<SMB2Packet> processPacket) {
      this.receiver = receiver
      if (this.receiver instanceof Connection) {
        ((Connection) this.receiver).smb2Converter = new StubMessageConverter()
      }
      this.processPacket = processPacket
    }

    @Override
    void write(SMB2Packet packet) throws TransportException {
      def response = processPacket.call(packet)

      if (response != null) {
        response.header.messageId = packet.header.messageId
        response.header.creditResponse = packet.header.creditRequest
        receiver.handle(new StubPacketData(response))
      } else {
        throw new TransportException("No response for " + packet)
      }
    }

    @Override
    void connect(InetSocketAddress remoteAddress) throws IOException {
      connected = true
    }

    @Override
    void disconnect() throws IOException {
      connected = false
    }

    @Override
    boolean isConnected() {
      return connected
    }
  }

  private static class StubPacketData extends SMB2PacketData {
    private SMB2Packet packet

    StubPacketData(SMB2Packet packet) throws Buffer.BufferException {
      super(new byte[0])
      this.packet = packet
    }

    @Override
    SMB2PacketHeader getHeader() {
      return packet.header
    }

    @Override
    protected void readHeader() throws Buffer.BufferException {
    }
  }

  private static class StubMessageConverter extends SMB2MessageConverter {
    private realConverter = new SMB2MessageConverter()
    @Override
    SMB2Packet readPacket(SMBPacket requestPacket, SMB2PacketData packetData) throws Buffer.BufferException {
      if (packetData instanceof StubPacketData) {
        return packetData.packet
      } else {
        return realConverter.readPacket(requestPacket, packetData)
      }
    }
  }
}
