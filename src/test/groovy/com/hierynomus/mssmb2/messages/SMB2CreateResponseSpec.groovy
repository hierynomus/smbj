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
package com.hierynomus.mssmb2.messages

import com.hierynomus.msdtyp.FileTime
import com.hierynomus.smb.SMBBuffer
import spock.lang.Specification

import javax.xml.bind.DatatypeConverter

class SMB2CreateResponseSpec extends Specification {

  def "should parse SMB2 Create Response without Maximal Content"() {
    given:
    String hexString1 = "fe534d4240000000000000000500010001000000000000000400000000000000000000000100000009000000004000000000000000000000000000000000000059000000010000006aa787efa59dd1016aa787efa59dd1016aa787efa59dd101954ff5efa59dd101000000000000000000000000000000001000000000000000030000001000000001000000100000000000000000000000"
    byte[] bytes1 = DatatypeConverter.parseHexBinary(hexString1)
    SMB2CreateResponse resp = new SMB2CreateResponse()

    when:
    resp.read(new SMBBuffer(bytes1))

    then:
    resp.getCreationTime() == new FileTime(131059200184264554L)
    Arrays.equals(([0x03, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00] as byte[]), resp.fileId.persistentHandle)
  }

  def "should parse SMB2 Create Response with STATUS_PENDING"() {
    given:
    def hex = "fe534d424000010003010000050002000300000000000000040000000000000001000000000000004100000800280000e73d1a019d13aca24830757ebad16519090000000000000000"
    def bytes = DatatypeConverter.parseHexBinary(hex)
    def resp = SMB2MessageConverter.newInstance().read(bytes)

    expect:
    resp instanceof SMB2CreateResponse
  }
}
