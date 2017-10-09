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
package com.hierynomus.mssmb2

import com.hierynomus.smb.SMBBuffer
import spock.lang.Specification
import spock.lang.Unroll

class SMB2FunctionsSpec extends Specification {

  def "should resolve absolute symlinks correctly"() {
    given:
    def original = "Public\\ProtocolDocs\\DailyDocs\\[MS-SMB].doc"
    def symlink = new SMB2Error.SymbolicLinkError()
    symlink.absolute = true
    symlink.unparsedPathLength = 0x2E
    symlink.substituteName = "\\??\\D:\\DonHall\\MiscDocuments\\PDocs"
    symlink.printName = "D:\\DonHall\\MiscDocuments\\PDocs"

    when:
    def target = SMB2Functions.resolveSymlinkTarget(original, symlink)

    then:
    target == "\\??\\D:\\DonHall\\MiscDocuments\\PDocs\\DailyDocs\\[MS-SMB].doc"
  }

  def "should resolve relative symlinks correctly"() {
    given:
    def original = "Public\\ProtocolDocs\\DailyDocs\\[MS-SMB].doc"
    def symlink = new SMB2Error.SymbolicLinkError()
    symlink.absolute = false
    symlink.unparsedPathLength = 0x2E
    symlink.substituteName = "..\\DonHall\\Documents\\PDocs"
    symlink.printName = "..\\DonHall\\Documents\\PDocs"

    when:
    def target = SMB2Functions.resolveSymlinkTarget(original, symlink)

    then:
    target == "DonHall\\Documents\\PDocs\\DailyDocs\\[MS-SMB].doc"
  }
}
