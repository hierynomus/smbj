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
import com.hierynomus.smb.SMBBuffer
import spock.lang.Specification

class SMB2LeaseCreateContextSpec extends Specification {
    static final LeaseKey KEY = new LeaseKey(ByteArrayUtils.parseHex("000102030405060708090a0b0c0d0e0f"))
    static final LeaseKey PARENT = new LeaseKey(ByteArrayUtils.parseHex("101112131415161718191a1b1c1d1e1f"))

    static String hex(byte[] b) { ByteArrayUtils.toHex(b) }

    def "V2 RH request with parent emits the exact 52-byte data blob"() {
        when:
        def data = SMB2LeaseCreateContext.v2(KEY, SMB2LeaseState.readHandle(), PARENT).toBytes()

        then:
        data.length == 52
        hex(data) ==
            "000102030405060708090a0b0c0d0e0f" + // LeaseKey
            "03000000" +                          // LeaseState = RH
            "04000000" +                          // Flags = PARENT_LEASE_KEY_SET
            "0000000000000000" +                  // LeaseDuration
            "101112131415161718191a1b1c1d1e1f" + // ParentLeaseKey
            "0000" +                              // Epoch = 0
            "0000"                                // Reserved
    }

    def "V2 RH request with parent wraps to the exact 76-byte create context"() {
        given:
        def buf = new SMBBuffer()

        when:
        int written = SMB2CreateContext.writeAll(buf, [SMB2LeaseCreateContext.v2(KEY, SMB2LeaseState.readHandle(), PARENT).toCreateContext()])

        then:
        written == 76
        hex(buf.getCompactData()) ==
            "00000000" + "1000" + "0400" + "0000" + "1800" + "34000000" + // TLV header
            "52714c73" +                          // "RqLs"
            "00000000" +                          // pad to data @ offset 24
            "000102030405060708090a0b0c0d0e0f" + "03000000" + "04000000" +
            "0000000000000000" + "101112131415161718191a1b1c1d1e1f" + "0000" + "0000"
    }

    def "V2 RH request without parent clears flag and zero-fills ParentLeaseKey"() {
        when:
        def data = SMB2LeaseCreateContext.v2(KEY, SMB2LeaseState.readHandle(), null).toBytes()

        then:
        data.length == 52
        hex(data) ==
            "000102030405060708090a0b0c0d0e0f" +
            "03000000" +
            "00000000" +                          // Flags = 0 (no parent)
            "0000000000000000" +
            "00000000000000000000000000000000" +  // ParentLeaseKey all-zero
            "0000" + "0000"
    }

    def "a zero parent key is treated as no parent"() {
        expect:
        SMB2LeaseCreateContext.v2(KEY, SMB2LeaseState.readHandle(), LeaseKey.zero()).flags == 0L
    }

    def "V1 request emits the exact 32-byte data blob (no parent/epoch)"() {
        when:
        def data = SMB2LeaseCreateContext.v1(KEY, SMB2LeaseState.SMB2_LEASE_READ_CACHING.value).toBytes()

        then:
        data.length == 32
        hex(data) ==
            "000102030405060708090a0b0c0d0e0f" + "01000000" + "00000000" + "0000000000000000"
    }

    def "epoch is always zero on a V2 request"() {
        when:
        def data = SMB2LeaseCreateContext.v2(KEY, SMB2LeaseState.readHandle(), PARENT).toBytes()

        then: "bytes at offset 0x30..0x31 (Epoch) are 0000"
        hex(data)[96..99] == "0000"
    }
}
