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

import spock.lang.Specification

class SIDSpec extends Specification {

  def "SID.EVERYONE should be 'S-1-1-0'"() {
    expect:
    SID.EVERYONE.toString() == "S-1-1-0"
  }

  def "should be able to parse simple SID strings"() {
    expect:
    SID.fromString("S-1-1-0") == SID.EVERYONE
  }

  def "should be able to parse complex SID strings"() {
    expect:
    SID.fromString("S-1-5-21-1234-5678-1357-500") == new SID((byte) 1, [0, 0, 0, 0, 0, 5] as byte[], [21, 1234, 5678, 1357, 500] as long[])
  }

  def "should be able to parse SID strings with hex identifier authority"() {
    expect:
    SID.fromString("S-1-0x36efabcd0123-21-1234-5678-1357-500") == new SID((byte) 1, [0x36, 0xef, 0xab, 0xcd, 0x01, 0x23] as byte[], [21, 1234, 5678, 1357, 500] as long[])
  }

  def "SID identity"() {
    given:
    SID s1 = new SID((byte) 1, [0, 0, 0, 0, 0, 1] as byte[], [0] as long[])
    SID s2 = new SID((byte) 1, [0, 0, 0, 0, 0, 1] as byte[], [0] as long[])

    expect:
    s1 == s2
    s1.hashCode() == s2.hashCode()
  }
}
