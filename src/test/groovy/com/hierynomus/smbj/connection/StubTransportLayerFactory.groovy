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

import com.hierynomus.mssmb2.SMB2Packet
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.protocol.transport.PacketHandlers
import com.hierynomus.protocol.transport.PacketReceiver
import com.hierynomus.protocol.transport.TransportException
import com.hierynomus.protocol.transport.TransportLayer
import com.hierynomus.smbj.transport.TransportLayerFactory

class StubTransportLayerFactory implements TransportLayerFactory<SMB2Packet> {
  private Closure<SMB2Packet> processPacket

  StubTransportLayerFactory(Closure<SMB2Packet> processPacket) {
    this.processPacket = processPacket
  }

  @Override
  TransportLayer<SMB2Packet> createTransportLayer(PacketHandlers<SMB2Packet> handlers, SmbConfig config) {
    return new StubTransportLayer(handlers.receiver, processPacket)
  }

  private static class StubTransportLayer implements TransportLayer<SMB2Packet> {
    private boolean connected
    private PacketReceiver<SMB2Packet> receiver
    private Closure<SMB2Packet> processPacket

    StubTransportLayer(PacketReceiver<SMB2Packet> receiver, Closure<SMB2Packet> processPacket) {
      this.receiver = receiver
      this.processPacket = processPacket
    }

    @Override
    void write(SMB2Packet packet) throws TransportException {
      def response = processPacket.call(packet)

      if (response != null) {
        response.header.messageId = packet.header.messageId
        response.header.creditResponse = packet.header.creditRequest
        receiver.handle(response)
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

}
