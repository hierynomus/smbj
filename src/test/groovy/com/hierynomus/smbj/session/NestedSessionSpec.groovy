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
package com.hierynomus.smbj.session

import com.hierynomus.mssmb2.SMB2MessageCommandCode
import com.hierynomus.protocol.transport.TransportException
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.common.SmbPath
import com.hierynomus.smbj.testing.PacketProcessor
import com.hierynomus.smbj.testing.StubAuthenticator
import com.hierynomus.smbj.testing.StubTransportLayerFactory
import spock.lang.Specification

/**
 * Tests the lifecycle of the connections that are opened under the hood for DFS targets.
 */
class NestedSessionSpec extends Specification {

  def commands = []
  def recorder = { req ->
    commands << [req.packet.header.message, req.packet.header.messageId]
    return null
  } as PacketProcessor
  def config = SmbConfig.builder()
    .withTransportLayerFactory(new StubTransportLayerFactory(new PacketProcessor.DefaultPacketProcessor().wrap(recorder)))
    .withAuthenticators(new StubAuthenticator.Factory())
    .build()
  def client = new SMBClient(config)
  def credentials = new AuthenticationContext("foo", "bar".toCharArray(), null)
  def target = new SmbPath("target", "share")

  def "should release the connection of a nested session when the session is logged off"() {
    given:
    def session = client.connect("root").authenticate(credentials)
    def nestedConnection = session.getNestedSession(target).connection

    expect:
    nestedConnection.isConnected()

    when:
    session.close()

    then:
    !nestedConnection.isConnected()
    !client.connect("target").is(nestedConnection)
  }

  def "should keep the connection of a nested session open while another user still has it leased"() {
    given:
    def session = client.connect("root").authenticate(credentials)
    def nestedConnection = session.getNestedSession(target).connection
    def otherUser = client.connect("target")

    when:
    session.close()

    then:
    otherUser.is(nestedConnection)
    nestedConnection.isConnected()
    client.connect("target").is(nestedConnection)
  }

  def "should create a new nested session when the connection of the cached one was lost"() {
    given:
    def session = client.connect("root").authenticate(credentials)
    def nested = session.getNestedSession(target)
    nested.connection.handleError(new TransportException("Connection reset"))

    when:
    def replacement = session.getNestedSession(target)

    then:
    !replacement.is(nested)
    !replacement.connection.is(nested.connection)
    replacement.connection.isConnected()
    session.getNestedSession(target).is(replacement)
  }

  def "should reuse the nested session as long as its connection is alive"() {
    given:
    def session = client.connect("root").authenticate(credentials)

    expect:
    session.getNestedSession(target).is(session.getNestedSession(target))
  }

  def "should not try to log off sessions on a connection that was lost"() {
    given:
    def connection = client.connect("root")
    connection.authenticate(credentials)
    commands.clear()

    when:
    connection.handleError(new TransportException("Connection reset"))

    then:
    !connection.isConnected()
    commands.every { it[0] != SMB2MessageCommandCode.SMB2_LOGOFF }
  }

  def "should close the kept-open directory handles before the sessions are logged off"() {
    given:
    def connection = client.connect("root")
    connection.authenticate(credentials)
    def events = []
    def directory = Mock(com.hierynomus.smbj.share.Directory)
    directory.closeSilently() >> { events << "directory closed"; commands.each { events << it[0] } }
    def key = connection.leaseManager.leaseKeyForPath("dir")
    def entry = new com.hierynomus.smbj.connection.LeaseEntry(key, null, 0x5L, "dir")
    entry.setCacheDirectory(directory)
    connection.leaseManager.register(entry)
    commands.clear()

    when:
    connection.close()

    then:
    events == ["directory closed"]
    commands.collect { it[0] }.contains(com.hierynomus.mssmb2.SMB2MessageCommandCode.SMB2_LOGOFF)
  }
}
