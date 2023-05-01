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
import com.hierynomus.msfscc.fileinformation.FileIdFullDirectoryInformation
import com.hierynomus.msfscc.fileinformation.FileInternalInformation
import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.mssmb2.SMB2ShareAccess
import com.hierynomus.security.bc.BCSecurityProvider
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.share.Directory
import com.hierynomus.smbj.share.DiskShare
import com.hierynomus.smbj.share.File
import spock.lang.Specification

import static com.hierynomus.mssmb2.SMB2CreateDisposition.FILE_OPEN

class IntegrationTest extends Specification {
  static final def IP = "127.0.0.1"
  static final def AUTH = new AuthenticationContext("smbj", "smbj".toCharArray(), null)
  static final def SHARE = "public"
  static final def FOLDER_THAT_EXISTS = "folder"
  static final def FILE_THAT_EXISTS = "test.txt"
  static final def FOLDER_THAT_DOES_NOT_EXIST = "foo"


  def config = SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_0).withEncryptData(true).withSigningRequired(true).withMultiProtocolNegotiate(true).withDfsEnabled(true).withSecurityProvider(new BCSecurityProvider())
  def client = _
  Connection connection = null

  def setup() {
    client = new SMBClient(config.build())
    connection = client.connect(IP)
  }

  def cleanup() {
    connection.close()
  }

  def "should be connected"() {
    expect:
    connection.connected
  }

  def "should authenticate"() {
    when:
    def session = connection.authenticate(AUTH)

    then:
    session.sessionId != null
  }

  def "should connect to share"() {
    when:
    def session = connection.authenticate(AUTH)
    def share = session.connectShare(SHARE)

    then:
    share instanceof DiskShare
    share.treeConnect.treeId != null
    share.isConnected()
  }

  def "should check directory existence"() {
    when:
    def session = connection.authenticate(AUTH)
    def share = session.connectShare(SHARE) as DiskShare

    then:
    share.folderExists(FOLDER_THAT_EXISTS)
    !share.folderExists(FOLDER_THAT_DOES_NOT_EXIST)
  }

  def "should be able to list directories"() {
    when:
    def session = connection.authenticate(AUTH)
    def share = session.connectShare(SHARE) as DiskShare
    def children = share.list(FOLDER_THAT_EXISTS)

    then:
    children.size() > 0
  }

  def "should be able to open directories"() {
    when:
    def session = connection.authenticate(AUTH)
    def share = session.connectShare(SHARE) as DiskShare
    def dir = share.open(FOLDER_THAT_EXISTS, EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL, FILE_OPEN, null)

    then:
    dir instanceof Directory
  }

  def "should be able to open files"() {
    when:
    def session = connection.authenticate(AUTH)
    def share = session.connectShare(SHARE) as DiskShare
    def dir = share.open(FILE_THAT_EXISTS, EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL, FILE_OPEN, null)

    then:
    dir instanceof File
  }

  def "should not fail closing connection twice"() {
    given:
    connection.close()

    when:
    connection.close()

    then:
    noExceptionThrown()
  }

  def "should be able to read fileID from FileIdBothDirectoryInformation"() {
    when:
    def session = connection.authenticate(AUTH)
    def share = session.connectShare(SHARE) as DiskShare
    def children = share.list(FOLDER_THAT_EXISTS)
    def firstChild = children.get(1);
    def firstChildFile = share.open(FOLDER_THAT_EXISTS + '\\' + firstChild.getFileName(), EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL, FILE_OPEN, null)
    def fileInternalInformation = firstChildFile.getFileInformation(FileInternalInformation.class)

    then:
    firstChild.fileId == fileInternalInformation.indexNumber // both refer to the same file ID
  }

  def "should be able to read fileID from FileIdFullDirectoryInformation"() {
    when:
    def session = connection.authenticate(AUTH)
    def share = session.connectShare(SHARE) as DiskShare
    def children = share.list(FOLDER_THAT_EXISTS, FileIdFullDirectoryInformation.class)
    def firstChild = children.get(1);
    def firstChildFile = share.open(FOLDER_THAT_EXISTS + '\\' + firstChild.getFileName(), EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL, FILE_OPEN, null)
    def fileInternalInformation = firstChildFile.getFileInformation(FileInternalInformation.class)

    then:
    firstChild.fileId == fileInternalInformation.indexNumber // both refer to the same file ID
  }


}
