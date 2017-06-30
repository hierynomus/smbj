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
import com.hierynomus.mssmb2.SMB2ShareAccess
import com.hierynomus.security.bc.BCSecurityProvider
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.share.Directory
import com.hierynomus.smbj.share.DiskShare
import com.hierynomus.smbj.share.File
import org.bouncycastle.jce.provider.BouncyCastleProvider
import spock.lang.Specification

import java.security.Security

import static com.hierynomus.mssmb2.SMB2CreateDisposition.FILE_OPEN

class IntegrationTest extends Specification {
  static final def IP = "172.16.93.193"
  static final def AUTH = new AuthenticationContext("jeroen", "jeroen".toCharArray(), null)
  static final def SHARE = "NewShare"
  static final def FOLDER_THAT_EXISTS = "api"
  static final def FILE_THAT_EXISTS = "README.md"
  static final def FOLDER_THAT_DOES_NOT_EXIST = "foo"


  def config = SmbConfig.builder().withSigningRequired(true).withSecurityProvider(new BCSecurityProvider()).build()
  def client = new SMBClient(config)

  def "should connect"() {
    when:
    def connection = client.connect(IP)

    then:
    connection.connected

    cleanup:
    connection.close()
  }

  def "should authenticate"() {
    when:
    def connection = client.connect(IP)
    def session = connection.authenticate(AUTH)

    then:
    session.sessionId != null

    cleanup:
    connection.close()
  }

  def "should connect to share"() {
    when:
    def connection = client.connect(IP)
    def session = connection.authenticate(AUTH)
    def share = session.connectShare(SHARE)
    connection.close()

    then:
    share instanceof DiskShare
    share.treeConnect.treeId != null
    !share.isConnected()

    cleanup:
    connection.close()
  }

  def "should check directory existence"() {
    when:
    def connection = client.connect(IP)
    def session = connection.authenticate(AUTH)
    def share = session.connectShare(SHARE) as DiskShare

    then:
    share.folderExists(FOLDER_THAT_EXISTS)
    !share.folderExists(FOLDER_THAT_DOES_NOT_EXIST)

    cleanup:
    connection.close()
  }

  def "should be able to list directories"() {
    when:
    def connection = client.connect(IP)
    def session = connection.authenticate(AUTH)
    def share = session.connectShare(SHARE) as DiskShare
    def children = share.list(FOLDER_THAT_EXISTS)

    then:
    children.size() > 0

    cleanup:
    connection.close()
  }

  def "should be able to open directories"() {
    when:
    def connection = client.connect(IP)
    def session = connection.authenticate(AUTH)
    def share = session.connectShare(SHARE) as DiskShare
    def dir = share.open(FOLDER_THAT_EXISTS, EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL, FILE_OPEN, null)

    then:
    dir instanceof Directory

    cleanup:
    connection.close()
  }

  def "should be able to open files"() {
    when:
    def connection = client.connect(IP)
    def session = connection.authenticate(AUTH)
    def share = session.connectShare(SHARE) as DiskShare
    def dir = share.open(FILE_THAT_EXISTS, EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL, FILE_OPEN, null)

    then:
    dir instanceof File

    cleanup:
    connection.close()
  }
}
