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

import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.share.DiskShare
import org.bouncycastle.jce.provider.BouncyCastleProvider
import spock.lang.Specification

import java.security.Security

class IntegrationTest extends Specification {
  def IP = "172.16.37.153"
  def AUTH = new AuthenticationContext("Administrator", "xeb1aLabs".toCharArray(), "")

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
    def share = session.connectShare("Go")
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
    def share = session.connectShare("Go") as DiskShare

    then:
    share.folderExists("api")
    !share.folderExists("foo")

    cleanup:
    connection.close()
  }
}
