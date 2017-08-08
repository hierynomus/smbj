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

import com.hierynomus.smb.SMBBuffer
import spock.lang.Specification

import javax.xml.bind.DatatypeConverter

class SMB2ChangeNotifyResponseSpec extends Specification {

  def "should parse notifications"() {
    given:
    String hexString1 = "fe534d4240000100000000000f000100010000000000000011000000000000000000000001000000050000605258000000000000000000000000000000000000090048003c0100001c000000030000001000000049006d00670033002e0070006e00670034000000080000002800000049006d00670033002e0070006e0067003a004100460050005f0041006600700049006e0066006f0048000000080000003a00000049006d00670033002e0070006e0067003a0063006f006d002e006100700070006c0065002e00710075006100720061006e00740069006e006500ff0034000000080000002800000049006d00670033002e0070006e0067003a004100460050005f0041006600700049006e0066006f0000000000080000006400000049006d00670033002e0070006e0067003a0063006f006d002e006100700070006c0065002e006d00650074006100640061007400610022f06b004d0044004900740065006d0049007300530063007200650065006e004300610070007400750072006500";
    byte[] bytes1 = DatatypeConverter.parseHexBinary(hexString1);
    SMB2ChangeNotifyResponse resp = new SMB2ChangeNotifyResponse();

    when:
    resp.read(new SMBBuffer(bytes1))

    then:
    resp.fileNotifyInfoList.size() == 5
    resp.fileNotifyInfoList.collect { it.fileName }.equals(
      ["Img3.png", "Img3.png:AFP_AfpInfo", "Img3.png:com.apple.quarantine", "Img3.png:AFP_AfpInfo", "Img3.png:com.apple.metadatakMDItemIsScreenCapture"]
    )
  }


  def "should handle STATUS_NOTIFY_CLEANUP"() {
    given:
    String hexString1 = "fe534d42400001000b0100000f000000030000000000000005000000000000000100000000000000610000e063580000000000000000000000000000000000000900480000000000";
    byte[] bytes1 = DatatypeConverter.parseHexBinary(hexString1);
    SMB2ChangeNotifyResponse resp = new SMB2ChangeNotifyResponse();

    when:
    resp.read(new SMBBuffer(bytes1))

    then:
    resp.fileNotifyInfoList.size() == 0
  }

}
