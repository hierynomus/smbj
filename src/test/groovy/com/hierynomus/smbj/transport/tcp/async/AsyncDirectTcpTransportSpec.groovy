package com.hierynomus.smbj.transport.tcp.async

import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.server.StubSmbServer
import spock.lang.Shared
import spock.lang.Specification

class AsyncDirectTcpTransportSpec extends Specification {

  @Shared
  def config = SmbConfig.builder().withTransportLayerFactory(new AsyncDirectTcpTransportFactory()).build()

  StubSmbServer server

  def setup() {
    server = new StubSmbServer()
  }

  def cleanup() {
    server.shutdown()
  }

  def "client should connect to AsyncDirectTcpTransport"() {
    given:
    server.registerResponse("com/hierynomus/smbj/transport/tcp/async/nego-response.pcap")
    server.start()
    def client = new SMBClient(config)

    when:
    def connection = client.connect("localhost", server.port)

    then:
    noExceptionThrown()
    connection.isConnected()
    connection.close()
  }
}
