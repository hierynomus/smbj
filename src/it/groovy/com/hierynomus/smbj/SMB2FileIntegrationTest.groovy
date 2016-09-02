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

import com.hierynomus.msfscc.fileinformation.FileInfo
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.session.Session
import com.hierynomus.smbj.share.DiskShare
import com.hierynomus.smbj.share.Share
import org.bouncycastle.jce.provider.BouncyCastleProvider
import spock.lang.Specification

import java.security.Security

class SMB2FileIntegrationTest extends Specification {

  DiskShare share
  Session session
  Connection connection
  SMBClient client

  def setupSpec() {
    if (!Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
      Security.addProvider(new BouncyCastleProvider())
    }
  }

  def setup() {
    client = new SMBClient()
    connection = client.connect("172.16.37.149")
    session = connection.authenticate(new AuthenticationContext("Administrator", "xeb1aLabs".toCharArray(), null))
    share = session.connectShare("Go") as DiskShare
  }

  def cleanup() {
    session.close()
    connection.close()
  }

  def "should check existence of file and directory"() {
    given:
    def dir = share.getFile("api")
    def file = share.getFile("README.md")

    expect:
    dir.exists()
    file.exists()
  }

  def "should list contents of share"() {
    given:
    def list = share.list("")

    expect:
    list.size() == 10

  }

  def "should correctly list read permissions of file"() {
    given:
    def file = share.getFile("README.md")

    expect:
    file.
  }
}
