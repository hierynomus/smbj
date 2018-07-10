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
import com.hierynomus.mssmb2.SMB2OplockLevel
import com.hierynomus.mssmb2.SMB2ShareAccess
import com.hierynomus.mssmb2.SMBApiException
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.event.AsyncCreateResponseNotification
import com.hierynomus.smbj.event.OplockBreakNotification
import com.hierynomus.smbj.event.handler.AbstractNotificationHandler
import com.hierynomus.smbj.event.handler.MessageIdCallback
import com.hierynomus.smbj.io.ArrayByteChunkProvider
import com.hierynomus.smbj.session.Session
import com.hierynomus.smbj.share.DiskEntry
import com.hierynomus.smbj.share.DiskShare
import com.hierynomus.smbj.transport.tcp.async.AsyncDirectTcpTransportFactory
import spock.lang.Specification
import spock.lang.Unroll

import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

import static com.hierynomus.mssmb2.SMB2CreateDisposition.FILE_CREATE
import static com.hierynomus.mssmb2.SMB2CreateDisposition.FILE_OPEN
import static com.hierynomus.mssmb2.SMB2CreateDisposition.FILE_OPEN_IF

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
    def ostream = file.getOutputStream(new LoggingProgressListener())
    try {
      byte[] buffer = new byte[4096];
      int len;
      while ((len = istream.read(buffer)) != -1) {
        ostream.write(buffer, 0, len);
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

  def "should able to async create"() {
    given:
    def path = "createAsync.txt"
    // In actual implementation, the path is not available for createResponse complete. Map is required.
    def messageIdPathMap = new ConcurrentHashMap<Long, String>()
    // Should call async listener, just calling dummy in test case
    def testSucceed = new AtomicBoolean(false)
    share.setNotificationHandler( new AbstractNotificationHandler() {

      @Override
      void handleAsyncCreateResponseNotification(
        AsyncCreateResponseNotification asyncCreateResponseNotification) {
        def createResponseFuture = asyncCreateResponseNotification.future
        def createResponse
        try {
          createResponse = createResponseFuture.get()
        } catch (Throwable t) {
          throw new IllegalStateException("Unable to get create response", t)
        }
        def getPath = messageIdPathMap.remove(createResponse.header.messageId)
        if(getPath == null) {
          System.out.println("Could not find path in map. Should not related to async create, ignored.")
          return
        }

        if(createResponse.header.status != NtStatus.STATUS_SUCCESS) {
          throw new IllegalStateException("Async create failed with status " + createResponse.header.status.value)
        }

        def diskEntry = share.getDiskEntry(getPath, new DiskShare.SMB2CreateResponseContext(createResponse, share))

        if(diskEntry != null) {
          // Should call async listener, just calling dummy in test case
          testSucceed.compareAndSet(false, true)
        }
      }

    })

    when:
    share.openAsync(path, null, null, EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE), null, SMB2ShareAccess.ALL, FILE_CREATE, null, new MessageIdCallback() {

      @Override
      void callback(long messageId) {
        messageIdPathMap.put(messageId, path)
      }
    })

    then:
    // 1 second should be enough for the whole process complete in docker
    Thread.sleep(1000L)

    expect:
    testSucceed.get() == true

    cleanup:
    share.rm(path)
    messageIdPathMap.clear()

  }

  def "should able to receive oplock break notification and response acknowledgement then receive acknowledgement response"() {
    given:
    def path = "createAsyncOplock.txt"
    // In actual implementation, the path is not available for createResponse complete. Map is required.
    def messageIdPathMap = new ConcurrentHashMap<Long, String>()
    // Should call async listener, just using hashmap as dummy in test case
    def messageIdDiskEntryMap = new ConcurrentHashMap<Long, DiskEntry>()
    def fileIdDiskEntryMap = new ConcurrentHashMap<String, DiskEntry>()
    def succeedBreakToLevel2 = new AtomicBoolean(false)
    def oplockBreakAcknowledgmentResponseSucceed = new AtomicBoolean(false)
    share.setNotificationHandler( new AbstractNotificationHandler() {

      @Override
      void handleAsyncCreateResponseNotification(
        AsyncCreateResponseNotification asyncCreateResponseNotification) {
        def createResponseFuture = asyncCreateResponseNotification.future
        def createResponse
        try {
          createResponse = createResponseFuture.get()
        } catch (Throwable t) {
          throw new IllegalStateException("Unable to get create response", t)
        }
        def getPath = messageIdPathMap.remove(createResponse.header.messageId)
        if(getPath == null) {
          System.out.println("Could not find path in map. Should not related to async create, ignored.")
          return
        }

        if(createResponse.header.status != NtStatus.STATUS_SUCCESS) {
          throw new IllegalStateException("Async create failed with status " + createResponse.header.status.value)
        }

        def diskEntry = share.getDiskEntry(getPath, new DiskShare.SMB2CreateResponseContext(createResponse, share))

        if(diskEntry != null) {
          // Should call async listener, just calling dummy in test case
          messageIdDiskEntryMap.put(createResponse.header.messageId, diskEntry)
          fileIdDiskEntryMap.put(diskEntry.fileId.toHexString(), diskEntry)
        }
      }

      @Override
      void handleOplockBreakNotification(OplockBreakNotification oplockBreakNotification) {
        def oplockBreakLevel = oplockBreakNotification.oplockLevel
        def getDiskEntry = fileIdDiskEntryMap.get(oplockBreakNotification.fileId.toHexString())
        if(getDiskEntry == null) {
          throw new IllegalStateException("Unable to get corresponding diskEntry!")
        }
        // Assume we already notify client and had succeed handled client cache to break
        if(oplockBreakLevel) {
          // In this test case, this code should only run exactly once.
          succeedBreakToLevel2.compareAndSet(false, true)
        }
        // Should return to client for handling the client cache, dummy in test case
        def oplockBreakAcknowledgmentResponse = getDiskEntry.acknowledgeOplockBreak(oplockBreakLevel)
        if(oplockBreakAcknowledgmentResponse.header.status == NtStatus.STATUS_SUCCESS) {
          // In this test case, this code should only run exactly once.
          oplockBreakAcknowledgmentResponseSucceed.compareAndSet(false, true)
        }
      }
    })

    when:
    def firstCreateMessageId = 0L
    share.openAsync(path, SMB2OplockLevel.SMB2_OPLOCK_LEVEL_EXCLUSIVE, null, EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE), null, SMB2ShareAccess.ALL, FILE_OPEN_IF, null, new MessageIdCallback() {

      @Override
      void callback(long messageId) {
        messageIdPathMap.put(messageId, path)
        firstCreateMessageId = messageId
      }
    })

    then:
    // 1 second should be enough for the whole process complete in docker
    Thread.sleep(1000L)
    def firstCreateDiskEntry = messageIdDiskEntryMap.remove(firstCreateMessageId)
    // another create to the same file with SMB2_OPLOCK_LEVEL_EXCLUSIVE to trigger oplock break notification in Server.
    def secondCreateMessageId = 0L
    share.openAsync(path, SMB2OplockLevel.SMB2_OPLOCK_LEVEL_EXCLUSIVE, null, EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE), null, SMB2ShareAccess.ALL, FILE_OPEN_IF, null, new MessageIdCallback() {

      @Override
      void callback(long messageId) {
        messageIdPathMap.put(messageId, path)
        secondCreateMessageId = messageId
      }
    })
    // 1 second should be enough for the whole process complete in docker
    Thread.sleep(1000L)
    def secondCreateDiskEntry = messageIdDiskEntryMap.remove(secondCreateMessageId)

    expect:
    firstCreateDiskEntry != null
    secondCreateDiskEntry != null
    succeedBreakToLevel2.get() == true
    oplockBreakAcknowledgmentResponseSucceed.get() == true

    cleanup:
    share.rm(path)
    messageIdPathMap.clear()
    messageIdDiskEntryMap.clear()
    fileIdDiskEntryMap.clear()

  }
}
