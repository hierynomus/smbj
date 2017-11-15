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
