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
package com.hierynomus.smbj.server

import org.slf4j.LoggerFactory

import java.util.concurrent.CopyOnWriteArrayList

/**
 * A stub server that accepts any number of TCP connections and answers the first request on each of them with the
 * canned SMB2 NEGOTIATE response. Every connection is then kept open and silent, until the test drops it with
 * {@link #resetConnections()} or {@link #closeConnections()}.
 */
class MultiConnectionStubServer implements Closeable {
  private static final def logger = LoggerFactory.getLogger(MultiConnectionStubServer.class)
  private static final String NEGOTIATE_RESPONSE = "com/hierynomus/smbj/transport/tcp/async/nego-response.pcap"

  private final ServerSocket serverSocket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())
  private final List<Socket> accepted = new CopyOnWriteArrayList<>()
  private final byte[] negotiateResponse = getClass().getClassLoader().getResourceAsStream(NEGOTIATE_RESPONSE).withCloseable { it.bytes }

  MultiConnectionStubServer() {
    Thread.start("Stub-Server-" + port) {
      try {
        while (!serverSocket.isClosed()) {
          Socket socket = serverSocket.accept()
          accepted.add(socket)
          Thread.start("Stub-Server-" + port + "-connection") { serve(socket) }
        }
      } catch (IOException ignored) {
        logger.debug("Stub server stopped")
      }
    }
  }

  int getPort() {
    return serverSocket.getLocalPort()
  }

  int getAcceptedCount() {
    return accepted.size()
  }

  /**
   * Abort all connections with a TCP RST, as a peer that crashed or a firewall that dropped the state would.
   */
  void resetConnections() {
    accepted.each {
      it.setSoLinger(true, 0)
      it.close()
    }
  }

  /**
   * Close all connections with a regular TCP FIN, as a server that is shutting down would.
   */
  void closeConnections() {
    accepted.each { it.close() }
  }

  @Override
  void close() {
    serverSocket.close()
    accepted.each { it.close() }
  }

  private void serve(Socket socket) {
    try {
      def input = new DataInputStream(socket.getInputStream())
      boolean negotiated = false
      while (true) {
        byte[] header = new byte[4]
        input.readFully(header)
        int length = ((header[1] & 0xFF) << 16) | ((header[2] & 0xFF) << 8) | (header[3] & 0xFF)
        input.readFully(new byte[length])
        if (!negotiated) {
          negotiated = true
          socket.getOutputStream().write(negotiateResponse)
          socket.getOutputStream().flush()
        }
      }
    } catch (IOException ignored) {
      logger.debug("Stub server connection ended")
    }
  }
}
