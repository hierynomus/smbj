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
package com.hierynomus.msdfsc

import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.security.jce.JceSecurityProvider
import com.hierynomus.smbj.DefaultConfig
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.connection.NegotiatedProtocol
import com.hierynomus.smbj.event.SMBEventBus
import com.hierynomus.smbj.session.Session
import com.hierynomus.smbj.transport.TransportLayer
import spock.lang.Specification

class UserHostSessionTableTest extends Specification {
  def "find and retrieve a session"() {
    given:
    def connection
    def client = Stub(SMBClient) {
      connect(_) >> connection
      connect(_, _) >> connection
    }
    def transport = Mock(TransportLayer)
    def bus = new SMBEventBus()
    connection = Stub(Connection, constructorArgs: [new DefaultConfig(), client, transport, bus]) {
      getRemoteHostname() >> "domain"
      getNegotiatedProtocol() >> new NegotiatedProtocol(SMB2Dialect.SMB_2_1, 8*1024*1024, 8*1024*1024, 8*1024*1024, true)
    }
    def auth = new AuthenticationContext("username", "password".toCharArray(), "domain")
    def session = new Session(123, connection, auth, bus, false, new JceSecurityProvider())
    def uhs = new UserHostSessionTable()


    when:
    uhs.register(session);
    def auth2 = new AuthenticationContext("username", "password".toCharArray(), "domain");
    def session2 = uhs.lookup(auth2, "domain");

    then:
    session.getConnection().getRemoteHostname() == "domain"
    session2 == session
  }

}
