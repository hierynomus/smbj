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
package com.hierynomus.msdtyp.sddl

import com.hierynomus.msdtyp.SID
import com.hierynomus.msdtyp.SecurityDescriptor
import com.hierynomus.msdtyp.ace.AceFlag
import com.hierynomus.msdtyp.ace.AceType
import com.hierynomus.smbj.common.SMBRuntimeException
import spock.lang.Specification

class SddlTest extends Specification {
  def "should parse simple file ACLs correctly"() {
    given:
    def sddl = "O:WDG:S-1-0-0D:PAI(A;;FRFX;;;S-1-5-21-1-2-3-500)(D;ID;GASD;;;S-1-0xFF-500)"

    when:
    def sd = Sddl.parse(sddl)

    then:
    sd != null
    sd.ownerSid == SID.parse("S-1-1-0")
    sd.groupSid == SID.parse("S-1-0-0")
    sd.sacl == null
    !sd.control.contains(SecurityDescriptor.Control.SP)
    sd.dacl != null
    sd.control.contains(SecurityDescriptor.Control.DP)
    sd.control.contains(SecurityDescriptor.Control.PD)
    sd.control.contains(SecurityDescriptor.Control.DI)
    sd.dacl.aces.size() == 2
    sd.dacl.aces.get(0).aceHeader.aceType == AceType.ACCESS_ALLOWED_ACE_TYPE
    sd.dacl.aces.get(0).aceHeader.aceFlags.isEmpty()
    sd.dacl.aces.get(0).sid == SID.parse("S-1-5-21-1-2-3-500")
    sd.dacl.aces.get(1).aceHeader.aceType == AceType.ACCESS_DENIED_ACE_TYPE
    sd.dacl.aces.get(1).aceHeader.aceFlags.size() == 1
    sd.dacl.aces.get(1).aceHeader.aceFlags.contains(AceFlag.INHERITED_ACE)
    sd.dacl.aces.get(1).sid == SID.parse("S-1-255-500")
  }

  def "should throw an exception on invalid SID input"() {
    given:
    def sddl = "O:WDG:S-1-0-0D:PAI(A;;FRFX;;;S-1-5-abc21-1-2-3-500)"

    when:
    Sddl.parse(sddl)

    then:
    thrown(SMBRuntimeException)
  }

  def "should throw an exception on conditional ACEs"() {
    given:
    def sddl = "D:(XA;FA;FRFX;;;BA;(@User.Title==\"PM\"))"

    when:
    Sddl.parse(sddl)

    then:
    thrown(SMBRuntimeException)
  }

  def "should throw an exception on resource attribute ACEs"() {
    given:
    def sddl = "D:(RA;CI;;;;S-1-1-0;(\"Project\",TS,0,\"Windows\",\"SQL\"))"

    when:
    Sddl.parse(sddl)

    then:
    thrown(SMBRuntimeException)
  }
}
