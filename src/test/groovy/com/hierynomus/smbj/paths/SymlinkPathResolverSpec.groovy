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
package com.hierynomus.smbj.paths

import com.hierynomus.mserref.NtStatus
import com.hierynomus.mssmb2.SMB2Error
import com.hierynomus.mssmb2.SMB2PacketHeader
import com.hierynomus.mssmb2.messages.SMB2CreateResponse
import com.hierynomus.smbj.common.SmbPath
import spock.lang.Shared
import spock.lang.Specification

class SymlinkPathResolverSpec extends Specification {

  @Shared
  def pathResolver = new SymlinkPathResolver(PathResolver.LOCAL)

  def "should resolve absolute symlinks correctly"() {
    given:
    def original = "Public\\ProtocolDocs\\DailyDocs\\[MS-SMB].doc"
    SMB2CreateResponse resp = getResponse(true, 0x2E, "\\??\\D:\\DonHall\\MiscDocuments\\PDocs", "D:\\DonHall\\MiscDocuments\\PDocs")

    when:
    def target = pathResolver.resolve(null, resp, new SmbPath("localhost", "test", original))

    then:
    target.path == "??\\D:\\DonHall\\MiscDocuments\\PDocs\\DailyDocs\\[MS-SMB].doc"
  }

  def "should resolve relative symlinks correctly"() {
    given:
    def original = "Public\\ProtocolDocs\\DailyDocs\\[MS-SMB].doc"
    def resp = getResponse(false, 0x2E, "..\\DonHall\\Documents\\PDocs", "..\\DonHall\\Documents\\PDocs")

    when:
    def target = pathResolver.resolve(null, resp, new SmbPath("localhost", "test", original))

    then:
    target.path == "DonHall\\Documents\\PDocs\\DailyDocs\\[MS-SMB].doc"
  }

  private SMB2CreateResponse getResponse(Boolean absolute, Integer unparsedPathLength, String substituteName, String printName) {
    def symlink = new SMB2Error.SymbolicLinkError()
    symlink['absolute'] = absolute
    symlink['unparsedPathLength'] = unparsedPathLength
    symlink['substituteName'] = substituteName
    symlink['printName'] = printName
    def error = new SMB2Error()
    error.errorData.add(symlink)
    def resp = Stub(SMB2CreateResponse) {
      getError() >> error
      getHeader() >> Stub(SMB2PacketHeader) {
        getStatusCode() >> NtStatus.STATUS_STOPPED_ON_SYMLINK.value
      }
    }
    resp
  }
}
