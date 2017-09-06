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

import com.hierynomus.mssmb2.SMB2ShareCapabilities
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.smb.SMBBuffer
import spock.lang.Specification

class SMB2TreeConnectResponseSpec extends Specification {

  def "should parse tree connects"() {
    given:
    String hexString1 = "fe534d42400000000000000003000100010000000000000003000000000000000000000001000000010400d40058000000000000000000000000000000000000100001000008000000000000ff011f00"

    byte[] bytes1 = ByteArrayUtils.parseHex(hexString1)
    SMB2TreeConnectResponse tcResponse = new SMB2TreeConnectResponse()

    when:
    tcResponse.read(new SMBBuffer(bytes1))

    then:
    tcResponse.getCapabilities() == EnumSet.noneOf(SMB2ShareCapabilities.class)
    tcResponse.getMaximalAccess() == 0x001f01ffL
    tcResponse.getShareFlags() == 0x800L
    tcResponse.isDiskShare()
  }
}
