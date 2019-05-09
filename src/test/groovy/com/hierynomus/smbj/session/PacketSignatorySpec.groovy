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
package com.hierynomus.smbj.session

import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.mssmb2.SMB2MessageConverter
import com.hierynomus.mssmb2.SMB2PacketData
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.security.bc.BCSecurityProvider
import spock.lang.Specification

class PacketSignatorySpec extends Specification {

  def "should verify signature of non-success packet"() {
    given:
    def packet = new SMB2MessageConverter().readPacket(null, new SMB2PacketData([0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x10, 0x00, 0x06, 0x00, 0x00, 0x80, 0x0e, 0x00, 0x20, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x46, 0xef, 0xdd, 0x50, 0xd6, 0xcd, 0xaa, 0x25, 0xba, 0xc7, 0xc4, 0xb5, 0xd4, 0x9a, 0x0e, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05] as byte[]))
    def signatory = new PacketSignatory(SMB2Dialect.SMB_2_1, new BCSecurityProvider())
    signatory.init([0x75, 0xc5, 0xcb, 0x91, 0x41, 0x9e, 0x3a, 0x45, 0xce, 0x9e, 0xf8, 0x69, 0xdf, 0xd3, 0xe2, 0xa8] as byte[])

    when:
    boolean verified = signatory.verify(packet)

    then:
    noExceptionThrown()
    verified
  }

  def "should verify signature of packet with padding"() {
    def packet = new SMB2MessageConverter().readPacket(null, new SMB2PacketData(ByteArrayUtils.parseHex("fe534d4240000100030100c0050001000900000000000000ba9e62000000000000000000010000009103001c041400001FEDE330C927BC01F83C3C0E07DCB0BA09000000000000000000000000000000")))
    def signatory = new PacketSignatory(SMB2Dialect.SMB_2_1, new BCSecurityProvider())
    signatory.init([0x75, 0xc5, 0xcb, 0x91, 0x41, 0x9e, 0x3a, 0x45, 0xce, 0x9e, 0xf8, 0x69, 0xdf, 0xd3, 0xe2, 0xa8] as byte[])

    when:
    boolean verified = signatory.verify(packet)

    then:
    noExceptionThrown()
    verified

  }
}
