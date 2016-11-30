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

class SIDTest extends Specification {

    def "SID.EVERYONE should be 'S-1-1-0'"() {
        expect:
        SID.EVERYONE.toString() == "S-1-1-0"
    }

    def "SID identity"() {
      SID s1 = new SID((byte) 1, [0, 0, 0, 0, 0, 1] as byte[], [0] as long[]);
      SID s2 = new SID((byte) 1, [0, 0, 0, 0, 0, 1] as byte[], [0] as long[]);
      s1 == s2
    }
}
