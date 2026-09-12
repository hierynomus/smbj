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
package com.hierynomus.smbj.transport.tcp.direct

import com.hierynomus.protocol.transport.PacketFactory
import com.hierynomus.protocol.transport.PacketHandlers
import com.hierynomus.protocol.transport.PacketReceiver
import com.hierynomus.protocol.transport.PacketSerializer
import spock.lang.Specification

import javax.net.SocketFactory
import java.net.InetSocketAddress
import java.net.ServerSocket

class DirectTcpTransportSpec extends Specification {

  def "disconnect stops PacketReader when transport already disconnected"() {
    given:
    def serverSocket = new ServerSocket(0)
    def acceptThread = Thread.start {
      serverSocket.accept()
    }

    def receiver = Mock(PacketReceiver)
    def handlers = Mock(PacketHandlers)
    handlers.getPacketFactory() >> Mock(PacketFactory)
    handlers.getReceiver() >> receiver
    handlers.getSerializer() >> Mock(PacketSerializer)

    def transport = Spy(new DirectTcpTransport(SocketFactory.getDefault(), 5000, handlers))

    when:
    transport.connect(new InetSocketAddress("127.0.0.1", serverSocket.localPort))
    acceptThread.join(5000)
    transport.isConnected() >> false
    transport.disconnect()
    waitForPacketReaderToStop("127.0.0.1", 5000)

    then:
    noExceptionThrown()
    findPacketReaderThread("127.0.0.1") == null

    cleanup:
    serverSocket.close()
  }

  private static Thread findPacketReaderThread(String host) {
    Thread.getAllStackTraces().keySet().find { it.name.startsWith("Packet Reader for $host") }
  }

  private static void waitForPacketReaderToStop(String host, long timeoutMs) {
    def deadline = System.currentTimeMillis() + timeoutMs
    while (System.currentTimeMillis() < deadline) {
      if (findPacketReaderThread(host) == null) {
        return
      }
      Thread.sleep(50)
    }
  }
}
