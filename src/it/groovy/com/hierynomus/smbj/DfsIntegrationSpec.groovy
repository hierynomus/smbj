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

import com.hierynomus.msdtyp.AccessMask
import com.hierynomus.mssmb2.SMB2CreateDisposition
import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.mssmb2.SMB2ShareAccess
import com.hierynomus.security.bc.BCSecurityProvider
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.session.Session
import com.hierynomus.smbj.share.DiskShare
import spock.lang.Ignore
import spock.lang.Specification

class DfsIntegrationSpec extends Specification {
  Session session
  Connection connection
  SMBClient client

  def setup() {
    def config = SmbConfig
      .builder()
      .withDialects(SMB2Dialect.SMB_2_1)
      .withMultiProtocolNegotiate(true)
      .withSigningRequired(true)
      .withDfsEnabled(true)
      .build()
    client = new SMBClient(config)
    connection = client.connect("127.0.0.1")
    session = connection.authenticate(new AuthenticationContext("smbj", "smbj".toCharArray(), null))
  }

  def cleanup() {
    session.logoff()
    connection.close()
  }

  def "should connect to DFS share"() {
    given:
    def share = session.connectShare("dfs")

    when:
    def list = (share as DiskShare).list("")

    then:
    list.fileName.contains("public")
    list.fileName.contains("user")

    cleanup:
    share.close()
  }

  def "should list contents of DFS virtual directory"() {
    given:
    def share = session.connectShare("dfs")

    when:
    def dir = (share as DiskShare).openDirectory("user", EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)

    then:
    dir.list().fileName.contains(".")

    cleanup:
    share.close()
  }

  def "should connect to fallback if first link is broken"() {
    given:
    def share = session.connectShare("dfs")

    when:
    def dir = (share as DiskShare).openDirectory("firstfail-public", EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)

    then:
    dir.list().fileName.contains(".")

    cleanup:
    share.close()
  }
}
