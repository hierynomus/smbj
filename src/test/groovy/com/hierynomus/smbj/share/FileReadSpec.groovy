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
package com.hierynomus.smbj.share

import com.hierynomus.msdtyp.AccessMask
import com.hierynomus.mserref.NtStatus
import com.hierynomus.msfscc.FileAttributes
import com.hierynomus.mssmb2.*
import com.hierynomus.mssmb2.messages.SMB2CreateRequest
import com.hierynomus.mssmb2.messages.SMB2CreateResponse
import com.hierynomus.mssmb2.messages.SMB2ReadRequest
import com.hierynomus.mssmb2.messages.SMB2ReadResponse
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.common.Check
import com.hierynomus.smbj.connection.BasicPacketProcessor
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.connection.StubAuthenticator
import com.hierynomus.smbj.connection.StubTransportLayerFactory
import spock.lang.Specification

import java.security.DigestOutputStream
import java.security.MessageDigest

class FileReadSpec extends Specification {
  private byte[] expectedDigest
  private byte[] fileData
  private MessageDigest digest
  private File file
  private Connection connection

  def setup() {
    fileData = randomData(42, 12345)

    def responder = new BasicPacketProcessor({ req ->
      if (req instanceof SMB2CreateRequest)
        return createResponse()
      if (req instanceof SMB2ReadRequest)
        return read(req, fileData)

      null
    })

    def config = SmbConfig.builder()
      .withReadBufferSize(1024)
      .withDfsEnabled(false)
      .withTransportLayerFactory(new StubTransportLayerFactory(responder.&processPacket))
      .withAuthenticators(new StubAuthenticator.Factory())
      .build()
    def client = new SMBClient(config)

    connection = client.connect("127.0.0.1")
    def session = connection.authenticate(new AuthenticationContext("username", "password".toCharArray(), "domain.com"))
    def share = session.connectShare("share") as DiskShare
    file = share.openFile(
      "file",
      EnumSet.of(AccessMask.GENERIC_READ),
      EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
      SMB2ShareAccess.ALL,
      SMB2CreateDisposition.FILE_OPEN,
      EnumSet.noneOf(SMB2CreateOptions.class)
    )
    digest = MessageDigest.getInstance("MD5")
    expectedDigest = digest.digest(fileData)
    digest.reset()
  }

  def cleanup() {
    connection.close()
  }

  def "should read entire file contents directly"() {
    when:
    def out = new DigestOutputStream(new ByteArrayOutputStream(), digest)
    def buffer = new byte[10]
    def fileOffset = 0 as long

    def bytesRead
    while ((bytesRead = file.read(buffer, fileOffset)) != -1) {
      out.write(buffer, 0, bytesRead)
      fileOffset += bytesRead
    }

    then:
    ByteArrayUtils.printHex(digest.digest()) == ByteArrayUtils.printHex(expectedDigest)
  }

  def "should read entire file contents directly with buffer offset"() {
    when:
    def out = new DigestOutputStream(new ByteArrayOutputStream(), digest)
    def buffer = new byte[256]
    def bufferOffset = 10
    def chunkSize = 100
    def fileOffset = 0 as long

    def bytesRead
    while ((bytesRead = file.read(buffer, fileOffset, bufferOffset, chunkSize)) != -1) {
      out.write(buffer, bufferOffset, bytesRead)
      fileOffset += bytesRead
    }

    then:
    ByteArrayUtils.printHex(digest.digest()) == ByteArrayUtils.printHex(expectedDigest)
  }

  def "should read entire file contents via input stream"() {
    when:
    def out = new DigestOutputStream(new ByteArrayOutputStream(), digest)
    def buffer = new byte[10]

    def input = file.getInputStream(null)
    def bytesRead
    while ((bytesRead = input.read(buffer)) != -1) {
      out.write(buffer, 0, bytesRead)
    }

    then:
    ByteArrayUtils.printHex(digest.digest()) == ByteArrayUtils.printHex(expectedDigest)
  }

  def "should read entire file contents via input stream with buffer offset"() {
    when:
    def out = new DigestOutputStream(new ByteArrayOutputStream(), digest)
    def buffer = new byte[256]
    def bufferOffset = 10
    def chunkSize = 100

    def input = file.getInputStream(null)
    def bytesRead
    while ((bytesRead = input.read(buffer, bufferOffset, chunkSize)) != -1) {
      out.write(buffer, bufferOffset, bytesRead)
    }

    then:
    ByteArrayUtils.printHex(digest.digest()) == ByteArrayUtils.printHex(expectedDigest)
  }

  def "should skip bytes at start of inputstream"() {
    given:
    def out = new ByteArrayOutputStream()
    def buffer = new byte[256]
    def input = file.getInputStream(null)
    def bytesRead

    when:
    input.skip(10000)

    while ((bytesRead = input.read(buffer)) != -1) {
      out.write(buffer, 0, bytesRead)
    }

    then:
    out.toByteArray() == fileData[10000..-1]
  }

  def "should skip bytes when started reading inputstream"() {
    given:
    def out = new ByteArrayOutputStream()
    def buffer = new byte[256]
    def input = file.getInputStream(null)
    def bytesRead

    when:
    out.write(input.read())
    input.skip(10000)

    while ((bytesRead = input.read(buffer)) != -1) {
      out.write(buffer, 0, bytesRead)
    }

    then:
    out.toByteArray()[0] == fileData[0]
    out.toByteArray()[1..-1] == fileData[10001..-1]
  }

  byte[] randomData(int seed, int length) {
    Random rng = new Random(seed)
    byte[] data = new byte[length]
    rng.nextBytes(data);
    data
  }

  SMB2Packet createResponse() {
    def response = new SMB2CreateResponse()
    response.header.status = NtStatus.STATUS_SUCCESS
    response.fileAttributes = EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL)
    response.fileId = new SMB2FileId(new byte[0], new byte[0])
    response
  }

  SMB2Packet read(SMB2ReadRequest req, byte[] data) {
    def offset = req.offset as int
    def length = req.getPayloadSize()

    if (offset + length > data.length) {
      length = data.length - offset
    }

    def response = new SMB2ReadResponse()

    if (length <= 0) {
      response.header.status = NtStatus.STATUS_END_OF_FILE
    } else {
      response.header.status = NtStatus.STATUS_SUCCESS
      response.data = Arrays.copyOfRange(data, offset, offset + length)
      response.dataLength = length
    }
    response
  }
}
