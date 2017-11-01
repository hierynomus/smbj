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
import com.hierynomus.smbj.connection.BasicPacketProcessor
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.connection.StubAuthenticator
import com.hierynomus.smbj.connection.StubTransportLayerFactory
import spock.lang.Specification

/**
 * Created by xuthus on 01.11.2017.
 */
class FileOutputStreamSpec extends Specification {
  private File file
  private Connection connection
  private ByteArrayOutputStream devNull

  def setup() {
    devNull = new ByteArrayOutputStream()
    def responder = new BasicPacketProcessor({ req ->
      if (req instanceof SMB2CreateRequest)
        return createResponse()
      if (req instanceof SMB2WriteRequest)
        return write(req)

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
    response.header.status = NtStatus.STATUS_SUCCESS
    response.fileAttributes = EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL)
    response.fileId = new SMB2FileId(new byte[0], new byte[0])
    response
  }

  SMB2WriteResponse write(SMB2WriteRequest req) {
    def response = new SMB2WriteResponse()
    response.header.status = NtStatus.STATUS_SUCCESS
    response.bytesWritten = req.maxPayloadSize
    req.byteProvider.writeChunk(devNull)
    response
  }

}
