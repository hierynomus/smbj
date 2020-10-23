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
import com.hierynomus.msfscc.FileAttributes
import com.hierynomus.msfscc.FileNotifyAction
import com.hierynomus.msfscc.fileinformation.FileStandardInformation
import com.hierynomus.mssmb2.SMB2ChangeNotifyFlags
import com.hierynomus.mssmb2.SMB2CompletionFilter
import com.hierynomus.mssmb2.SMB2CreateDisposition
import com.hierynomus.mssmb2.SMB2ShareAccess
import com.hierynomus.mssmb2.SMBApiException
import com.hierynomus.mssmb2.messages.SMB2Cancel
import com.hierynomus.mssmb2.messages.SMB2ChangeNotifyResponse
import com.hierynomus.protocol.commons.concurrent.Futures
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.common.SMBRuntimeException
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.io.ArrayByteChunkProvider
import com.hierynomus.smbj.session.Session
import com.hierynomus.smbj.share.DiskShare
import com.hierynomus.smbj.transport.tcp.async.AsyncDirectTcpTransportFactory
import spock.lang.Specification
import spock.lang.Unroll

import java.nio.charset.StandardCharsets

import static com.hierynomus.mssmb2.SMB2CreateDisposition.*

class SMB2DirectoryIntegrationTest extends Specification {

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

  def "should correctly detect folder existence"() {
    given:
    share.mkdir("im_a_directory")
    def src = share.openFile("im_a_file", EnumSet.of(AccessMask.GENERIC_WRITE), null, SMB2ShareAccess.ALL, FILE_OVERWRITE_IF, null)
    src.write(new ArrayByteChunkProvider("Hello World!".getBytes(StandardCharsets.UTF_8), 0))
    src.close()

    expect:
    share.folderExists("im_a_directory")
    !share.folderExists("im_a_file")
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

  def "should cancel ChangeNotify request"() {
    given:
    share.mkdir("to_be_watched")
    def dir = share.openDirectory("to_be_watched", EnumSet.of(AccessMask.GENERIC_ALL), null, SMB2ShareAccess.ALL, FILE_OPEN, null)
    dir.deleteOnClose()

    def watch = dir.watchAsync(EnumSet.of(SMB2CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME), true)

    when:
    watch.cancel(true)
    def cancel = Futures.get(watch, SMBRuntimeException.Wrapper)

    then:
    noExceptionThrown()
    cancel.fileNotifyInfoList.size() == 0
  }

  def "should watch changes"() {
    given:
    share.mkdir("directory")
    def directory = share.openDirectory("directory",
                                   EnumSet.of(AccessMask.GENERIC_READ),
                                   EnumSet.of(FileAttributes.FILE_ATTRIBUTE_DIRECTORY),
                                   SMB2ShareAccess.ALL,
                                   SMB2CreateDisposition.FILE_OPEN,
                                   null)

    when:
    def notifyResponseFuture = directory.watchAsync(EnumSet.of(SMB2CompletionFilter.FILE_NOTIFY_CHANGE_SIZE, SMB2CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME, SMB2CompletionFilter.FILE_NOTIFY_CHANGE_LAST_WRITE), false)
    def file = share.openFile("directory/TestNotify.txt",
                                       EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE, AccessMask.DELETE),
                                       EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                                       SMB2ShareAccess.ALL,
                                       SMB2CreateDisposition.FILE_CREATE,
                                       null)
    file.write("Testing 123 123".getBytes(StandardCharsets.UTF_8), 0)
    file.close()

    then:
    def notifyResponse = notifyResponseFuture.get()
    notifyResponse.fileNotifyInfoList != null
    notifyResponse.fileNotifyInfoList.size() == 1
    def fileNotifyInfo01 = notifyResponse.fileNotifyInfoList.get(0)
    fileNotifyInfo01.fileName == "TestNotify.txt"
    fileNotifyInfo01.action == FileNotifyAction.FILE_ACTION_ADDED
    directory.close()

    cleanup:
    share.rmdir("directory", true)
  }

}
