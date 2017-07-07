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
import com.hierynomus.mssmb2.SMB2ShareAccess
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.session.Session
import com.hierynomus.smbj.share.Directory
import com.hierynomus.smbj.share.DiskShare
import com.hierynomus.smbj.share.File
import org.bouncycastle.jce.provider.BouncyCastleProvider
import spock.lang.Specification

import java.security.Security

import static com.hierynomus.mssmb2.SMB2CreateDisposition.FILE_OPEN

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
    connection = client.connect("172.16.93.194")
    session = connection.authenticate(new AuthenticationContext("jeroen", "jeroen".toCharArray(), null))
    share = session.connectShare("NewShare") as DiskShare
  }

  def cleanup() {
    connection.close()
  }

  def "should list contents of share"() {
    given:
    def list = share.list("")

    expect:
    list.size() == 6
  }

  def "should correctly list read permissions of file"() {
    given:
    def file = share.open("README.md", EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL, FILE_OPEN, null)
    def dir = share.open("api", EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL, FILE_OPEN, null)

    expect:
    file instanceof File
    dir instanceof Directory
  }

  def "should transfer big file to share"() {
    given:
    def file = share.openFile("bigfile", EnumSet.of(AccessMask.FILE_WRITE_DATA), null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OVERWRITE_IF, null)
    def bytes = new byte[32 * 1024 * 1024 + 10]
    Random.newInstance().nextBytes(bytes)
    def istream = new ByteArrayInputStream(bytes)

    when:
    def ostream = file.getOutputStream()
    byte[] buffer = new byte[4096];
    int len;
    while ((len = istream.read(buffer)) != -1) {
      ostream.write(buffer, 0, len);
    }
    ostream.close()
    file.close()

    then:
    share.fileExists("bigfile")
    share.rm("bigfile")
  }
}
