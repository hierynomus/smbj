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
import com.hierynomus.msfscc.fileinformation.FileStandardInformation
import com.hierynomus.mssmb2.SMB2CreateDisposition
import com.hierynomus.mssmb2.SMB2ShareAccess
import com.hierynomus.mssmb2.SMBApiException
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.io.ArrayByteChunkProvider
import com.hierynomus.smbj.session.Session
import com.hierynomus.smbj.share.DiskShare
import com.hierynomus.smbj.transport.tcp.async.AsyncDirectTcpTransportFactory
import spock.lang.Specification
import spock.lang.Unroll

import java.nio.charset.StandardCharsets

import static com.hierynomus.mssmb2.SMB2CreateDisposition.*

class SMB2FileIntegrationTest extends Specification {

  DiskShare share
  Session session
  Connection connection
  SMBClient client

  def setup() {
    def config = SmbConfig
      .builder()
      .withMultiProtocolNegotiate(true)
    .withTransportLayerFactory(new AsyncDirectTcpTransportFactory<>())
      .withSigningRequired(true).build()
    client = new SMBClient(config)
    connection = client.connect("127.0.0.1")
    session = connection.authenticate(new AuthenticationContext("smbj", "smbj".toCharArray(), null))
    share = session.connectShare("user") as DiskShare
  }

  def cleanup() {
    connection.close()
  }

  def "should list contents of empty share"() {
    when:
    def list = share.list("")

    then:
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
    e.statusCode == NtStatus.STATUS_SHARING_VIOLATION.value
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
    def ostream = file.getOutputStream(new LoggingProgressListener())
    try {
      byte[] buffer = new byte[4096]
      int len
      while ((len = istream.read(buffer)) != -1) {
        ostream.write(buffer, 0, len)
      }
    } finally {
      istream.close()
      ostream.close()
      file.close()
    }

    then:
    share.fileExists("bigfile")

    when:
    def readBytes = new byte[32 * 1024 * 1024 + 10]
    def readFile = share.openFile("bigfile", EnumSet.of(AccessMask.FILE_READ_DATA), null, SMB2ShareAccess.ALL, FILE_OPEN, null)
    try {
      def remoteIs = readFile.getInputStream(new LoggingProgressListener())
      try {
        def offset = 0
        while (offset < readBytes.length) {
          def read = remoteIs.read(readBytes, offset, readBytes.length - offset)
          if (read > 0) {
            offset += read
          } else {
            break
          }
        }
      } finally {
        remoteIs.close()
      }
    } finally {
      readFile.close()
    }

    then:
    readBytes == bytes

    cleanup:
    share.rm("bigfile")
  }
  def "should append to the file"() {
    given:
    def file = share.openFile("appendfile", EnumSet.of(AccessMask.FILE_WRITE_DATA), null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN_IF, null)
    def bytes = new byte[1024 * 1024]
    Random.newInstance().nextBytes(bytes)
    def istream = new ByteArrayInputStream(bytes)

    when:
    def ostream = file.getOutputStream(new LoggingProgressListener())
    try {
      byte[] buffer = new byte[4096]
      int len
      while ((len = istream.read(buffer)) != -1) {
        ostream.write(buffer, 0, len)
      }
    } finally {
      istream.close()
      ostream.close()
      file.close()
    }

    then:
    share.fileExists("appendfile")

    when:
    def appendfile = share.openFile("appendfile", EnumSet.of(AccessMask.FILE_WRITE_DATA), null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN_IF, null)
    def bytes2 = new byte[1024 * 1024]
    Random.newInstance().nextBytes(bytes2)
    def istream2 = new ByteArrayInputStream(bytes2)
    ostream = appendfile.getOutputStream(new LoggingProgressListener(),true)
    try {
      byte[] buffer = new byte[4096]
      int len
      while ((len = istream2.read(buffer)) != -1) {
        ostream.write(buffer, 0, len)
      }
    } finally {
      istream2.close()
      ostream.close()
      appendfile.close()
    }

    then:
    share.fileExists("appendfile")

    when:
    def readBytes = new byte[2* 1024 * 1024]
    def readFile = share.openFile("appendfile", EnumSet.of(AccessMask.FILE_READ_DATA), null, SMB2ShareAccess.ALL, FILE_OPEN, null)
    try {
      def remoteIs = readFile.getInputStream(new LoggingProgressListener())
      try {
        def offset = 0
        while (offset < readBytes.length) {
          def read = remoteIs.read(readBytes, offset, readBytes.length - offset)
          if (read > 0) {
            offset += read
          } else {
            break
          }
        }
      } finally {
        remoteIs.close()
      }
    } finally {
      readFile.close()
    }

    then:
    readBytes == [bytes,bytes2].flatten()

    cleanup:
    share.rm("appendfile")
  }

  def "should be able to copy files remotely"() {
    given:
    def src = share.openFile("srcFile", EnumSet.of(AccessMask.GENERIC_WRITE), null, SMB2ShareAccess.ALL, FILE_OVERWRITE_IF, null)
    src.write(new ArrayByteChunkProvider("Hello World!".getBytes(StandardCharsets.UTF_8), 0))
    src.close()

    src = share.openFile("srcFile", EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL, FILE_OPEN, null)
    def dst = share.openFile("dstFile", EnumSet.of(AccessMask.FILE_WRITE_DATA), null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OVERWRITE_IF, null)

    when:
    src.remoteCopyTo(dst)

    then:
    share.fileExists("dstFile")
    def srcSize = src.getFileInformation(FileStandardInformation.class).endOfFile
    def dstSize = dst.getFileInformation(FileStandardInformation.class).endOfFile
    srcSize == dstSize

    cleanup:
    try {
      share.rm("srcFile")
    } catch (SMBApiException e) {
      // Ignored
    }

    try {
      share.rm("dstFile")
    } catch (SMBApiException e) {
      // Ignored
    }
  }

  def "should correctly detect file and folder existence"() {
    given:
    share.mkdir("im_a_directory")
    def src = share.openFile("im_a_file", EnumSet.of(AccessMask.GENERIC_WRITE), null, SMB2ShareAccess.ALL, FILE_OVERWRITE_IF, null)
    src.write(new ArrayByteChunkProvider("Hello World!".getBytes(StandardCharsets.UTF_8), 0))
    src.close()

    expect:
    share.fileExists("im_a_file")
    share.folderExists("im_a_directory")
    !share.folderExists("im_a_file")
    !share.fileExists("im_a_directory")
    !share.fileExists("i_do_not_exist")
    !share.folderExists("i_do_not_exist")

    cleanup:
    share.rm("im_a_file")
    share.rmdir("im_a_directory", false)
  }

  @Unroll
  def "should not fail if #method response is DELETE_PENDING for directory"() {
    given:
    def dir = share.openDirectory("to_be_removed", EnumSet.of(AccessMask.GENERIC_WRITE), null, SMB2ShareAccess.ALL, FILE_CREATE, null)
    dir.close()
    dir = share.openDirectory("to_be_removed", EnumSet.of(AccessMask.GENERIC_ALL), null, SMB2ShareAccess.ALL, FILE_OPEN, null)
    dir.deleteOnClose()

    when:
    func(share)

    then:
    noExceptionThrown()

    where:
    method | func
    "rmdir" | { s -> s.rmdir("to_be_removed", false) }
    "folderExists" | { s -> s.folderExists("to_be_removed") }
  }

  @Unroll
  def "should not fail if #method response is DELETE_PENDING for file"() {
    given:
    def textFile = share.openFile("test.txt", EnumSet.of(AccessMask.GENERIC_WRITE), null, SMB2ShareAccess.ALL, FILE_CREATE, null)
    textFile.write(new ArrayByteChunkProvider("Hello World!".getBytes(StandardCharsets.UTF_8), 0))
    textFile.close()
    textFile = share.openFile("test.txt", EnumSet.of(AccessMask.GENERIC_ALL), null, SMB2ShareAccess.ALL, FILE_OPEN, null)
    textFile.deleteOnClose()

    when:
    func(share)

    then:
    noExceptionThrown()

    where:
    method | func
    "rm" | { s -> s.rm("test.txt") }
    "fileExists" | { s -> s.fileExists("test.txt") }
  }

  def "should not fail if folderExists response is DELETE_PENDING"() {
    given:
    def dir = share.openDirectory("to_be_removed", EnumSet.of(AccessMask.GENERIC_WRITE), null, SMB2ShareAccess.ALL, FILE_CREATE, null)
    dir.close()
    dir = share.openDirectory("to_be_removed", EnumSet.of(AccessMask.GENERIC_ALL), null, SMB2ShareAccess.ALL, FILE_OPEN, null)
    dir.deleteOnClose()

    when:
    share.folderExists("to_be_removed")

    then:
    noExceptionThrown()
  }

  def "should not fail if fileExists response is DELETE_PENDING"() {
    given:
    def textFile = share.openFile("test.txt", EnumSet.of(AccessMask.GENERIC_WRITE), null, SMB2ShareAccess.ALL, FILE_CREATE, null)
    textFile.write(new ArrayByteChunkProvider("Hello World!".getBytes(StandardCharsets.UTF_8), 0))
    textFile.close()
    textFile = share.openFile("test.txt", EnumSet.of(AccessMask.GENERIC_ALL), null, SMB2ShareAccess.ALL, FILE_OPEN, null)
    textFile.deleteOnClose()

    when:
    share.fileExists("test.txt")

    then:
    noExceptionThrown()
  }
}
