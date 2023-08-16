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

import com.hierynomus.msdtyp.FileTime
import com.hierynomus.mserref.NtStatus
import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.mssmb2.SMBApiException
import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.mssmb2.SMB2MessageCommandCode
import com.hierynomus.mssmb2.messages.SMB2NegotiateRequest
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse
import com.hierynomus.mssmb2.messages.SMB2TreeConnectRequest
import com.hierynomus.mssmb2.SMB2GlobalCapability
import com.hierynomus.mssmb2.messages.SMB2TreeConnectResponse
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.paths.DFSPathResolver
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.event.ConnectionClosed
import com.hierynomus.smbj.event.SMBEvent
import com.hierynomus.smbj.event.SMBEventBus
import com.hierynomus.smbj.event.SessionLoggedOff
import com.hierynomus.protocol.transport.TransportException
import com.hierynomus.smbj.testing.PacketProcessor.NoOpPacketProcessor
import com.hierynomus.smbj.testing.PacketProcessor.DefaultPacketProcessor
import com.hierynomus.smbj.testing.StubAuthenticator
import com.hierynomus.smbj.testing.StubTransportLayerFactory
import net.engio.mbassy.listener.Handler
import spock.lang.Specification

class ConnectionSpec extends Specification {

  def bus = new SMBEventBus()
  def packetProcessor = new NoOpPacketProcessor()
  def config = smbConfig(packetProcessor)

  private SmbConfig smbConfig(packetProcessor) {
    SmbConfig.builder()
      .withTransportLayerFactory(new StubTransportLayerFactory(new DefaultPacketProcessor().wrap(packetProcessor)))
      .withAuthenticators(new StubAuthenticator.Factory())
      .build()
  }
  def client = new SMBClient(config, bus)

  def "should not close Sessions if force-closed"() {
    given:
    def listener = new EventPersister()
    bus.subscribe(listener)
    def connect = client.connect("localhost")

    when:
    connect.close(true)

    then:
    listener.events.size() == 1
    listener.events[0] == new ConnectionClosed("localhost", 445)
  }

  def "should close Sessions if closed"() {
    given:
    def listener = new EventPersister()
    bus.subscribe(listener)
    def connect = client.connect("localhost")
    def session = connect.authenticate(new AuthenticationContext("foo", "bar".toCharArray(), null))

    when:
    connect.close()

    then:
    listener.events.size() == 2
    listener.events[0] == new SessionLoggedOff(session.sessionId)
    listener.events[1] == new ConnectionClosed("localhost", 445)
  }

  def "should handle STATUS_NOT_SUPPORTED on dialect negotiation"() {
    given:
    config = smbConfig({ req ->
      def resp = new SMB2NegotiateResponse()
      resp.header.statusCode = NtStatus.STATUS_NOT_SUPPORTED.value
      return resp
    })
    client = new SMBClient(config)

    when:
    client.connect("foo")

    then:
    def exc = thrown(SMBApiException)
    exc.statusCode == NtStatus.STATUS_NOT_SUPPORTED.value
  }

  def "should report STATUS_NETWORK_SESSION_EXPIRED to client application"() {
    given:
    config = smbConfig({ req ->
      req = req.packet
      if (req instanceof SMB2TreeConnectRequest) {
        def resp = new SMB2TreeConnectResponse()
        resp.header.statusCode = NtStatus.STATUS_NETWORK_SESSION_EXPIRED.value
        return resp
      }
    })
    client = new SMBClient(config)

    when:
    def conn = client.connect("foo")
    def sess = conn.authenticate(new AuthenticationContext("smbj", "smbj".toCharArray(), null))
    sess.connectShare("foo")

    then:
    def exc = thrown(SMBApiException)
    exc.statusCode == NtStatus.STATUS_NETWORK_SESSION_EXPIRED.value
  }

  def "should initialise session flags in context once authenticated"() {
    given:
    def connect = client.connect("localhost")
    def session = connect.authenticate(new AuthenticationContext("foo", "bar".toCharArray(), null))

    when:
    def guest = session.isGuest()

    then:
    !guest
  }

  def "should not add DFS path resolver if server does not support DFS"() {
    given:
    config = smbConfig({ req ->
      def resp = new SMB2NegotiateResponse()
      resp.header.statusCode = NtStatus.STATUS_SUCCESS.value
      resp.dialect = SMB2Dialect.SMB_3_0
      resp.capabilities = EnumSet.noneOf(SMB2GlobalCapability.class)
      resp.systemTime = FileTime.now();
      return resp
    })
    config.dfsEnabled = true

    when:
    def conn = client.connect("foo")

    then:
    !(conn.pathResolver instanceof DFSPathResolver)
  }

  def "should add DFS path resolver if server supports DFS"() {
    given:
    config = smbConfig({ req ->
      def resp = new SMB2NegotiateResponse()
      resp.header.statusCode = NtStatus.STATUS_SUCCESS.value
      resp.dialect = SMB2Dialect.SMB_3_0
      resp.capabilities = EnumSet.of(SMB2GlobalCapability.SMB2_GLOBAL_CAP_DFS)
      resp.systemTime = FileTime.now();
      return resp
    })
    config.dfsEnabled = true
    client = new SMBClient(config)

    when:
    def conn = client.connect("foo")

    then:
    conn.pathResolver instanceof DFSPathResolver
  }

  class EventPersister {
    def events = [] as List<SMBEvent>

    @Handler
    def handle(SMBEvent event) {
      this.events.add(event)
    }
  }
}
