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
import com.hierynomus.msfscc.FileAttributes
import com.hierynomus.msfscc.FileNotifyAction
import com.hierynomus.mssmb2.SMB2CompletionFilter
import com.hierynomus.mssmb2.SMB2CreateDisposition
import com.hierynomus.mssmb2.SMB2ShareAccess
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.session.Session
import com.hierynomus.smbj.share.DiskShare
import com.hierynomus.smbj.transport.tcp.async.AsyncDirectTcpTransportFactory
import spock.lang.Specification

import java.nio.charset.StandardCharsets

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

  def "should notify change"() {

    given:
    share.mkdir("directory")
    def directory = share.openDirectory("directory",
                                   EnumSet.of(AccessMask.GENERIC_READ),
                                   EnumSet.of(FileAttributes.FILE_ATTRIBUTE_DIRECTORY),
                                   SMB2ShareAccess.ALL,
                                   SMB2CreateDisposition.FILE_OPEN,
                                   null)

    when:
    def notifyResponseFuture = directory.sendChangeNotifyRequest(EnumSet.of(SMB2CompletionFilter.FILE_NOTIFY_CHANGE_SIZE, SMB2CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME, SMB2CompletionFilter.FILE_NOTIFY_CHANGE_LAST_WRITE),
                                              65535,
                                              false)
    def testNotifyFile001 = share.openFile("TestNotify.txt",
                                       EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE, AccessMask.DELETE),
                                       EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                                       SMB2ShareAccess.ALL,
                                       SMB2CreateDisposition.FILE_CREATE,
                                       null)
    testNotifyFile001.write("Testing 123 123".getBytes(StandardCharsets.UTF_8), 0)

    then:
    def notifyResponse = notifyResponseFuture.get()
    notifyResponse.fileNotifyInfoList != null
    notifyResponse.fileNotifyInfoList.size() == 1
    def fileNotifyInfo01 = notifyResponse.fileNotifyInfoList.get(0)
    fileNotifyInfo01.fileName == "TestNotify.txt"
    fileNotifyInfo01.action == FileNotifyAction.FILE_ACTION_ADDED

    cleanup:
    testNotifyFile001.deleteOnClose()
    testNotifyFile001.close()
    directory.close()
    share.rmdir("directory", true)
  }

}
