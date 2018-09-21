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

import com.hierynomus.protocol.commons.ByteArrayUtils

class SMB2WriteResponseSpec extends AbstractPacketReadSpec {

  def "should parse write response"() {
    given:
    String hexString1 = "fe534d4240000000000000000900010001000000000000004d00000000000000000000000100000061000000007400000000000000000000000000000000000011000000002000000000000000000000"
    byte[] bytes1 = ByteArrayUtils.parseHex(hexString1)

    when:
    def response = convert(bytes1)

    then:
    response.class == SMB2WriteResponse.class
    with(response as SMB2WriteResponse) { r ->
      r.bytesWritten == 8192
    }
  }
}
