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
package com.hierynomus.mssmb2.messages.create

import com.hierynomus.mssmb2.LeaseKey
import com.hierynomus.mssmb2.SMB2LeaseState
import com.hierynomus.protocol.commons.ByteArrayUtils
import spock.lang.Specification
import spock.lang.Unroll

class SMB2LeaseResponseContextSpec extends Specification {
    static final LeaseKey KEY = new LeaseKey(ByteArrayUtils.parseHex("000102030405060708090a0b0c0d0e0f"))
    static final LeaseKey PARENT = new LeaseKey(ByteArrayUtils.parseHex("101112131415161718191a1b1c1d1e1f"))

    static final byte[] V2_RH = ByteArrayUtils.parseHex(
        "000102030405060708090a0b0c0d0e0f" + "03000000" + "04000000" + "0000000000000000" +
        "101112131415161718191a1b1c1d1e1f" + "0500" + "0000")
    static final byte[] V1_R = ByteArrayUtils.parseHex(
        "000102030405060708090a0b0c0d0e0f" + "01000000" + "00000000" + "0000000000000000")

    def "parses a V2 response granting RH with parent + epoch"() {
        when:
        def r = SMB2LeaseResponseContext.read(V2_RH)

        then:
        r.isV2()
        r.getLeaseKey() == KEY
        r.getLeaseState() == 0x3L
        r.isReadHandleGranted()
        r.getParentLeaseKey() == PARENT
        r.getEpoch() == 5
    }

    def "parses a V1 response (no parent/epoch)"() {
        when:
        def r = SMB2LeaseResponseContext.read(V1_R)

        then:
        !r.isV2()
        r.getLeaseState() == 0x1L
        !r.isReadHandleGranted()
        r.getParentLeaseKey() == null
        r.getEpoch() == 0
    }

    @Unroll
    def "DataLength #len disambiguates to v2=#v2"() {
        expect:
        SMB2LeaseResponseContext.read(new byte[len]).isV2() == v2

        where:
        len | v2
        32  | false
        52  | true
    }

    def "a malformed DataLength throws"() {
        when:
        SMB2LeaseResponseContext.read(new byte[40])
        then:
        thrown(IllegalArgumentException)
    }

    def "round-trips a V2 request blob through the parser"() {
        when:
        def r = SMB2LeaseResponseContext.read(
            SMB2LeaseCreateContext.v2(KEY, SMB2LeaseState.readHandle(), PARENT).toBytes())

        then:
        r.getLeaseKey() == KEY
        r.getLeaseState() == 0x3L
        r.getParentLeaseKey() == PARENT
        r.getEpoch() == 0
    }
}
