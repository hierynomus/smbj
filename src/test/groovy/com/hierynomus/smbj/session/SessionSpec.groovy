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

import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.connection.NegotiatedProtocol
import com.hierynomus.smbj.event.SMBEventBus
import com.hierynomus.smbj.server.ServerList
import spock.lang.Specification

class SessionSpec extends Specification {

  def "share name cannot contain '\\'"() {
    given:
    def config = SmbConfig.createDefaultConfig()
    def connection = Stub(Connection, constructorArgs: [config, null, Mock(SMBEventBus), new ServerList()]) {
      getNegotiatedProtocol() >> new NegotiatedProtocol(SMB2Dialect.SMB_2_0_2, 100, 100, 100, true)
    }
    def session = new Session(connection, config, null, null, null, null, null)

    when:
    session.connectShare("foo\\bar")

    then:
    def ex = thrown(IllegalArgumentException)
    ex.message.contains("foo\\bar")
  }
}
