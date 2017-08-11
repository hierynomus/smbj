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
import com.hierynomus.mserref.NtStatus
import com.hierynomus.mssmb2.SMB2CreateDisposition
import com.hierynomus.mssmb2.SMB2ShareAccess
import com.hierynomus.mssmb2.SMBApiException
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.io.ArrayByteChunkProvider
import com.hierynomus.smbj.session.Session
import com.hierynomus.smbj.share.DiskShare
import spock.lang.Specification
import spock.lang.Unroll

import java.nio.charset.StandardCharsets

import static com.hierynomus.mssmb2.SMB2CreateDisposition.FILE_CREATE
import static com.hierynomus.mssmb2.SMB2CreateDisposition.FILE_OPEN

class SMB2FileIntegrationTest extends Specification {

  DiskShare share
  Session session
  Connection connection
  SMBClient client

//  def setupSpec() {
//    if (!Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
//      Security.addProvider(new BouncyCastleProvider())
//    }
//  }

  def setup() {
    def config = SmbConfig
      .builder()
      .withMultiProtocolNegotiate(true)
      .withSigningRequired(true).build()
    client = new SMBClient(config)
    connection = client.connect("172.16.93.221")
    session = connection.authenticate(new AuthenticationContext("jeroen", "jeroen".toCharArray(), null))
    share = session.connectShare("NewShare") as DiskShare
  }

  def cleanup() {
    connection.close()
  }

  def "should list contents of empty share"() {
    given:
    def list = share.list("")

    expect:
    list.size() == 2
    list.get(0).fileName == "."
    list.get(1).fileName == ".."
  }

  @Unroll
  def "should create file and list contents of share"() {
    given:
    def f = share.openFile("test", EnumSet.of(AccessMask.GENERIC_ALL), null, SMB2ShareAccess.ALL, FILE_CREATE, null)
    f.close()

    expect:
    share.list(path).collect { it.fileName } contains "test"

    cleanup:
    share.rm("test")

    where:
    path << ["", null]
  }

  def "should create directory and list contents"() {
    given:
    share.mkdir("folder-1")

    expect:
    share.list("").collect { it.fileName } contains "folder-1"
    share.list("folder-1").collect { it.fileName } == [".", ".."]

    cleanup:
    share.rmdir("folder-1", true)
  }

  def "should read file contents of file in directory"() {
    given:
    share.mkdir("api")
    def textFile = share.openFile("api\\test.txt", EnumSet.of(AccessMask.GENERIC_WRITE), null, SMB2ShareAccess.ALL, FILE_CREATE, null)
    textFile.write(new ArrayByteChunkProvider("Hello World!".getBytes(StandardCharsets.UTF_8), 0))
    textFile.close()

    when:
    def read = share.openFile("api\\test.txt", EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL, FILE_OPEN, null)

    then:
    def is = read.getInputStream()
    is.readLines() == ["Hello World!"]

    cleanup:
    is?.close()
    read.close()
    share.rmdir("api", true)
  }

  def "should delete locked file"() {
    given:
    def lockedFile = share.openFile("locked", EnumSet.of(AccessMask.GENERIC_WRITE), null, EnumSet.noneOf(SMB2ShareAccess.class), FILE_CREATE, null)

    when:
    share.rm("locked")

    then:
    def e = thrown(SMBApiException.class)
    e.status == NtStatus.STATUS_SHARING_VIOLATION
    share.list("").collect { it.fileName } contains "locked"

    cleanup:
    lockedFile.close()
    share.rm("locked")
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
