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

import com.hierynomus.mssmb2.messages.SMB2Echo
import com.hierynomus.protocol.transport.TransportException
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.event.ConnectionClosed
import com.hierynomus.smbj.event.SMBEventBus
import com.hierynomus.smbj.server.MultiConnectionStubServer
import com.hierynomus.smbj.transport.tcp.async.AsyncDirectTcpTransportFactory
import com.hierynomus.smbj.transport.tcp.direct.DirectTcpTransportFactory
import net.engio.mbassy.listener.Handler
import spock.lang.AutoCleanup
import spock.lang.Specification
import spock.lang.Timeout
import spock.util.concurrent.PollingConditions

import javax.net.SocketFactory

/**
 * Tests that {@link SMBClient} does not hand out cached connections after the peer is gone, over real TCP sockets.
 */
@Timeout(30)
class ConnectionLossSpec extends Specification {

  @AutoCleanup
  def server = new MultiConnectionStubServer()
  @AutoCleanup
  def otherServer = new MultiConnectionStubServer()

  def sockets = new BreakableSocketFactory()
  def bus = new SMBEventBus()
  def closedEvents = []
  @AutoCleanup
  def client = new SMBClient(SmbConfig.builder().withSocketFactory(sockets).build(), bus)
  def eventually = new PollingConditions(timeout: 5)

  def setup() {
    bus.subscribe(new Object() {
      @Handler
      void closed(ConnectionClosed event) {
        closedEvents << event
      }
    })
  }

  def "should not return a cached connection after the server dropped it, even if the connection is still shared"() {
    given:
    def first = client.connect("localhost", server.port)
    def shared = client.connect("localhost", server.port)

    expect:
    shared.is(first)

    when:
    server.resetConnections()

    then:
    eventually.eventually {
      assert !first.isConnected()
    }

    when:
    def replacement = client.connect("localhost", server.port)

    then:
    !replacement.is(first)
    replacement.isConnected()
    server.acceptedCount == 2
  }

  def "should not return a cached connection after the server closed it"() {
    given:
    def first = client.connect("localhost", server.port)

    when:
    server.closeConnections()

    then:
    eventually.eventually {
      assert !first.isConnected()
    }
    !client.connect("localhost", server.port).is(first)
  }

  def "should not return a cached connection after the server dropped it on the #name transport"() {
    given:
    def transportClient = new SMBClient(SmbConfig.builder().withTransportLayerFactory(factory).build(), bus)
    def first = transportClient.connect("localhost", server.port)

    when:
    server.resetConnections()

    then:
    eventually.eventually {
      assert !first.isConnected()
    }
    !transportClient.connect("localhost", server.port).is(first)

    cleanup:
    transportClient.close()

    where:
    name     | factory
    "direct" | new DirectTcpTransportFactory()
    "async"  | new AsyncDirectTcpTransportFactory()
  }

  def "should not return a cached connection after a write failed that the reader did not notice"() {
    given:
    def first = client.connect("localhost", server.port)
    sockets.failWrites = true

    when:
    first.send(new SMB2Echo(first.negotiatedProtocol.dialect))

    then:
    thrown(TransportException)
    !first.isConnected()

    when:
    sockets.failWrites = false
    def replacement = client.connect("localhost", server.port)

    then:
    !replacement.is(first)
    replacement.isConnected()
  }

  def "should keep returning a healthy connection while another connection is evicted"() {
    given:
    def healthy = client.connect("localhost", otherServer.port)
    def broken = client.connect("localhost", server.port)

    when:
    server.resetConnections()

    then:
    eventually.eventually {
      assert !broken.isConnected()
    }
    client.connect("localhost", otherServer.port).is(healthy)
    healthy.isConnected()
    otherServer.acceptedCount == 1
  }

  def "should not evict the replacement when the evicted connection is closed later"() {
    given:
    def first = client.connect("localhost", server.port)
    server.resetConnections()
    eventually.eventually {
      assert !first.isConnected()
    }
    def replacement = client.connect("localhost", server.port)
    closedEvents.clear()

    when:
    first.close()
    first.close()
    first.close(true)

    then:
    noExceptionThrown()
    closedEvents.isEmpty()
    client.connect("localhost", server.port).is(replacement)
    replacement.isConnected()
  }

  def "should publish ConnectionClosed once when a dead connection is closed"() {
    given:
    def connection = client.connect("localhost", server.port)
    server.resetConnections()
    eventually.eventually {
      assert !connection.isConnected()
    }

    when:
    connection.close()
    connection.close()

    then:
    noExceptionThrown()
    closedEvents.size() == 1
  }

  /**
   * Hands out real sockets, but lets writes fail with a broken pipe on demand, without the socket noticing.
   */
  static class BreakableSocketFactory extends SocketFactory {
    volatile boolean failWrites

    @Override
    Socket createSocket(String host, int port) throws IOException {
      def factory = this
      return new Socket(host, port) {
        @Override
        OutputStream getOutputStream() throws IOException {
          def real = super.getOutputStream()
          return new OutputStream() {
            @Override
            void write(int b) throws IOException {
              check()
              real.write(b)
            }

            @Override
            void write(byte[] b, int off, int len) throws IOException {
              check()
              real.write(b, off, len)
            }

            @Override
            void flush() throws IOException {
              real.flush()
            }

            private void check() {
              if (factory.failWrites) {
                throw new IOException("Broken pipe")
              }
            }
          }
        }
      }
    }

    @Override
    Socket createSocket(String host, int port, InetAddress localHost, int localPort) {
      throw new UnsupportedOperationException()
    }

    @Override
    Socket createSocket(InetAddress host, int port) {
      throw new UnsupportedOperationException()
    }

    @Override
    Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) {
      throw new UnsupportedOperationException()
    }
  }
}
