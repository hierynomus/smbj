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
import com.hierynomus.mssmb2.messages.SMB2WriteRequest
import com.hierynomus.mssmb2.messages.SMB2WriteResponse
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.testing.PacketProcessor.DefaultPacketProcessor
import com.hierynomus.smbj.testing.StubAuthenticator
import com.hierynomus.smbj.testing.StubTransportLayerFactory
import spock.lang.Specification

class FileOutputStreamSpec extends Specification {
  private File file
  private Connection connection
  private ByteArrayOutputStream devNull

  def setup() {
    devNull = new ByteArrayOutputStream()
    def responder = new DefaultPacketProcessor().wrap({ req ->
      if (req.packet instanceof SMB2CreateRequest)
        return createResponse()
      if (req.packet instanceof SMB2WriteRequest)
        return write(req.packet)

      null
    })

    def config = SmbConfig.builder()
      .withReadBufferSize(1024)
      .withDfsEnabled(false)
      .withTransportLayerFactory(new StubTransportLayerFactory(responder))
      .withAuthenticators(new StubAuthenticator.Factory())
      .build()
    def client = new SMBClient(config)

    connection = client.connect("127.0.0.1")
    def session = connection.authenticate(new AuthenticationContext("username", "password".toCharArray(), "domain.com"))
    def share = session.connectShare("share") as DiskShare
    file = share.openFile(
      "file",
      EnumSet.of(AccessMask.GENERIC_WRITE),
      EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
      SMB2ShareAccess.ALL,
      SMB2CreateDisposition.FILE_OPEN_IF,
      EnumSet.noneOf(SMB2CreateOptions.class)
    )
  }

  def cleanup() {
    connection.close()
  }

  def "should allow to close FileOutputStream after closing PrintWriter using it"() {
    given:
        FileOutputStream stream = file.outputStream
    when:
        stream.withCloseable { out ->
          out.withPrintWriter { writer ->
            writer.println "abcdef"
          }
        }
    then:
        notThrown(NullPointerException)
    then:
        stream.isClosed
  }

  def "should close FileOutputStream after withWriter"() {
    given:
        FileOutputStream stream = file.outputStream
    when:
        stream.withWriter { writer ->
          writer.println "abcdef"
        }
    then:
        notThrown(NullPointerException)
    then:
        stream.isClosed
  }

  SMB2Packet createResponse() {
    def response = new SMB2CreateResponse()
    response.header.statusCode = NtStatus.STATUS_SUCCESS.value
    response.fileAttributes = EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL)
    response.fileId = new SMB2FileId(new byte[0], new byte[0])
    response
  }

  SMB2WriteResponse write(SMB2WriteRequest req) {
    def response = new SMB2WriteResponse()
    response.header.statusCode = NtStatus.STATUS_SUCCESS.value
    response.bytesWritten = req.maxPayloadSize
    req.byteProvider.writeChunk(devNull)
    response
  }

}
