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
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.share.Directory
import com.hierynomus.smbj.share.DiskShare
import com.hierynomus.smbj.share.File
import org.bouncycastle.jce.provider.BouncyCastleProvider
import spock.lang.Specification

import java.security.Security

class IntegrationTest extends Specification {
  def IP = "172.16.37.153"
  def AUTH = new AuthenticationContext("Administrator", "xeb1aLabs".toCharArray(), "")
  def SHARE = "Go"
  def FOLDER_THAT_EXISTS = "api"
  def FILE_THAT_EXISTS = "something"
  def FOLDER_THAT_DOES_NOT_EXIST = "foo"

  def setupSpec() {
    if (!Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
      Security.addProvider(new BouncyCastleProvider())
    }
  }

  def "should connect"() {
    given:
    def client = new SMBClient()

    when:
    def connection = client.connect(IP)

    then:
    connection.connected

    cleanup:
    connection.close()
  }

  def "should authenticate"() {
    given:
    def client = new SMBClient()

    when:
    def connection = client.connect(IP)
    def session = connection.authenticate(AUTH)

    then:
    session.sessionId != null

    cleanup:
    connection.close()
  }

  def "should connect to share"() {
    given:
    def client = new SMBClient()

    when:
    def connection = client.connect(IP)
    def session = connection.authenticate(AUTH)
    def share = session.connectShare(SHARE)
    connection.close()

    then:
    share instanceof DiskShare
    share.treeConnect.treeId != null
    !share.isConnected()
  }

  def "should check directory existence"() {
    given:
    def client = new SMBClient()

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
    given:
    def client = new SMBClient()

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
    given:
    def client = new SMBClient()

    when:
    def connection = client.connect(IP)
    def session = connection.authenticate(AUTH)
    def share = session.connectShare(SHARE) as DiskShare
    def dir = share.open(FOLDER_THAT_EXISTS, AccessMask.GENERIC_READ.value)

    then:
    dir instanceof Directory

    cleanup:
    connection.close()
  }

  def "should be able to open files"() {
    given:
    def client = new SMBClient()

    when:
    def connection = client.connect(IP)
    def session = connection.authenticate(AUTH)
    def share = session.connectShare(SHARE) as DiskShare
    def dir = share.open(FILE_THAT_EXISTS, AccessMask.GENERIC_READ.value)

    then:
    dir instanceof File

    cleanup:
    connection.close()
  }
}
