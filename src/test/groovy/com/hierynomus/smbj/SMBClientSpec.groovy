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
package com.hierynomus.smbj

import com.hierynomus.smbj.connection.BasicPacketProcessor
import com.hierynomus.smbj.connection.StubTransportLayerFactory
import spock.lang.Specification

class SMBClientSpec extends Specification {

  def processor = new BasicPacketProcessor({ req -> null })
  def config = SmbConfig.builder().withTransportLayerFactory(new StubTransportLayerFactory(processor.&processPacket)).build()
  def client = new SMBClient(config)

  def "should return same connection for same host/port combo"() {
    given:
    def con1 = client.connect("aHost", 4242)

    when:
    def con2 = client.connect("aHost", 4242)

    then:
    con1 == con2
  }

  def "should return different connection for different port on same host"() {
    given:
    def con1 = client.connect("aHost", 4242)

    when:
    def con2 = client.connect("aHost", 6666)

    then:
    con1 != con2
  }

  def "should return different connection for different host"() {
    given:
    def con1 = client.connect("hostA")

    when:
    def con2 = client.connect("hostB")

    then:
    con1 != con2
  }

  def "should not return connection that was closed when connecting to same host"() {
    given:
    def con1 = client.connect("hostA")
    con1.close()

    when:
    def con2 = client.connect("hostA")

    then:
    con1 != con2
  }
}
