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
package com.hierynomus.msdtyp

import com.hierynomus.msdtyp.ace.AceFlags
import com.hierynomus.msdtyp.ace.AceType
import com.hierynomus.msdtyp.ace.AceTypes
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.smb.SMBBuffer
import spock.lang.Specification

import static com.hierynomus.msdtyp.SecurityDescriptor.Control.*
import static com.hierynomus.msdtyp.ace.AceFlags.INHERITED_ACE
import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toEnumSet

class SecurityDescriptorSpec extends Specification {
  def "should decode security descriptor"() {
    given:
    String hex = "010004841400000030000000000000004c0000000105000000000005150000008c2d23f408cdaa9b272443ebef0300000105000000000005150000008c2d23f408cdaa9b272443eb01020000020084000500000001001800bd0002000102000000000005200000002702000000102400ff011f000105000000000005150000008c2d23f408cdaa9b272443ebef03000000101400ff011f0001010000000000010000000000101800ff011f000102000000000005200000002002000000101400ff011f00010100000000000512000000"
    byte[] bytes = ByteArrayUtils.parseHex(hex)

    when:
    def sd = SecurityDescriptor.read(new SMBBuffer(bytes))

    then:
    sd.control == EnumSet.of(DP, DI, SR)

    sd.ownerSid == SID.fromString("S-1-5-21-4095946124-2611662088-3947045927-1007")

    sd.groupSid == SID.fromString("S-1-5-21-4095946124-2611662088-3947045927-513")

    sd.dacl.revision == 2 as byte
    sd.dacl.aces.size() == 5

    sd.dacl.aces.get(0).aceHeader.aceType == AceType.ACCESS_DENIED_ACE_TYPE
    sd.dacl.aces.get(0).aceHeader.aceFlags == EnumSet.noneOf(AceFlags.class)
    sd.dacl.aces.get(0).sid == SID.fromString("S-1-5-32-551")
    sd.dacl.aces.get(0).accessMask == 0x000200bd

    sd.dacl.aces.get(1).aceHeader.aceType == AceType.ACCESS_ALLOWED_ACE_TYPE
    sd.dacl.aces.get(1).aceHeader.aceFlags == EnumSet.of(INHERITED_ACE)
    sd.dacl.aces.get(1).sid == SID.fromString("S-1-5-21-4095946124-2611662088-3947045927-1007")
    sd.dacl.aces.get(1).accessMask == 0x001f01ff

    sd.dacl.aces.get(2).aceHeader.aceType == AceType.ACCESS_ALLOWED_ACE_TYPE
    sd.dacl.aces.get(2).aceHeader.aceFlags == EnumSet.of(INHERITED_ACE)
    sd.dacl.aces.get(2).sid == SID.fromString("S-1-1-0")
    sd.dacl.aces.get(2).accessMask == 0x001f01ff

    sd.dacl.aces.get(3).aceHeader.aceType == AceType.ACCESS_ALLOWED_ACE_TYPE
    sd.dacl.aces.get(3).aceHeader.aceFlags == EnumSet.of(INHERITED_ACE)
    sd.dacl.aces.get(3).sid == SID.fromString("S-1-5-32-544")
    sd.dacl.aces.get(3).accessMask == 0x001f01ff

    sd.dacl.aces.get(4).aceHeader.aceType == AceType.ACCESS_ALLOWED_ACE_TYPE
    sd.dacl.aces.get(4).aceHeader.aceFlags == EnumSet.of(INHERITED_ACE)
    sd.dacl.aces.get(4).sid == SID.fromString("S-1-5-18")
    sd.dacl.aces.get(4).accessMask == 0x001f01ff

    sd.sacl == null
  }

  def "should encode security descriptor"() {
    given:
    def sd = new SecurityDescriptor(
      EnumSet.of(DP, DI, SR),
      SID.fromString("S-1-5-21-4095946124-2611662088-3947045927-1007"),
      SID.fromString("S-1-5-21-4095946124-2611662088-3947045927-513"),
      null,
      new ACL(
        2 as byte,
        [
          AceTypes.accessDeniedAce(
            EnumSet.noneOf(AceFlags.class),
            toEnumSet(0x000200bd, AccessMask.class),
            SID.fromString("S-1-5-32-551")
          ),
          AceTypes.accessAllowedAce(
            EnumSet.of(INHERITED_ACE),
            toEnumSet(0x001f01ff, AccessMask.class),
            SID.fromString("S-1-5-21-4095946124-2611662088-3947045927-1007")
          ),
          AceTypes.accessAllowedAce(
            EnumSet.of(INHERITED_ACE),
            toEnumSet(0x001f01ff, AccessMask.class),
            SID.fromString("S-1-1-0")
          ),
          AceTypes.accessAllowedAce(
            EnumSet.of(INHERITED_ACE),
            toEnumSet(0x001f01ff, AccessMask.class),
            SID.fromString("S-1-5-32-544")
          ),
          AceTypes.accessAllowedAce(
            EnumSet.of(INHERITED_ACE),
            toEnumSet(0x001f01ff, AccessMask.class),
            SID.fromString("S-1-5-18")
          )
        ]
      )
    )

    when:
    def buffer = new SMBBuffer()
    sd.write(buffer)
    def bytes = buffer.getCompactData()

    then:
    bytes == ByteArrayUtils.parseHex("010004841400000030000000000000004C0000000105000000000005150000008C2D23F408CDAA9B272443EBEF0300000105000000000005150000008C2D23F408CDAA9B272443EB01020000020084000500000001001800BD0002000102000000000005200000002702000000102400FF011F000105000000000005150000008C2D23F408CDAA9B272443EBEF03000000101400FF011F0001010000000000010000000000101800FF011F000102000000000005200000002002000000101400FF011F00010100000000000512000000")
  }
}
