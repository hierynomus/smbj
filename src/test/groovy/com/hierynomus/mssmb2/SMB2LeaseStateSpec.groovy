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

import com.hierynomus.protocol.commons.EnumWithValue
import spock.lang.Specification
import spock.lang.Unroll

import java.util.EnumSet

import static com.hierynomus.mssmb2.SMB2LeaseState.SMB2_LEASE_HANDLE_CACHING
import static com.hierynomus.mssmb2.SMB2LeaseState.SMB2_LEASE_READ_CACHING

class SMB2LeaseStateSpec extends Specification {

    @Unroll
    def "state #s -> R=#r H=#h W=#w RH=#rh"() {
        expect:
        SMB2LeaseState.isRead(s) == r
        SMB2LeaseState.isHandle(s) == h
        SMB2LeaseState.isWrite(s) == w
        SMB2LeaseState.isReadHandle(s) == rh

        where:
        s    | r     | h     | w     | rh
        0x0L | false | false | false | false
        0x1L | true  | false | false | false
        0x3L | true  | true  | false | true
        0x5L | true  | false | true  | false
        0x7L | true  | true  | true  | true
        0x2L | false | true  | false | false
    }

    def "readHandle() is 0x3"() {
        expect:
        SMB2LeaseState.readHandle() == 0x3L
    }

    def "EnumUtils round-trips R+H to 0x3 and back"() {
        expect:
        EnumWithValue.EnumUtils.toLong(EnumSet.of(SMB2_LEASE_READ_CACHING, SMB2_LEASE_HANDLE_CACHING)) == 0x3L
        EnumWithValue.EnumUtils.toEnumSet(0x3L, SMB2LeaseState.class) ==
            EnumSet.of(SMB2_LEASE_READ_CACHING, SMB2_LEASE_HANDLE_CACHING)
    }
}
