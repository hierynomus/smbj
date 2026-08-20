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

import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.smb.SMBBuffer
import spock.lang.Specification

class SMB2CreateContextSpec extends Specification {

    static final byte[] NAME_A = "AbCd".getBytes("US-ASCII")          // 41 62 43 64
    static final byte[] NAME_B = "WxYz".getBytes("US-ASCII")          // 57 78 59 7a
    static final byte[] DATA_A = [0x11] * 8 as byte[]                 // 8 bytes
    static final byte[] DATA_B = [0x22] * 4 as byte[]                 // 4 bytes

    // Context 0 {AbCd, 8x0x11}: Next=32, NameOffset=16, NameLen=4, DataOffset=24, DataLen=8
    static final String CTX0 =
        "20000000" + "1000" + "0400" + "0000" + "1800" + "08000000" +
        "41624364" + "00000000" + "1111111111111111"
    // Context 1 {WxYz, 4x0x22} (last): Next=0, DataLen=4, no trailing pad
    static final String CTX1 =
        "00000000" + "1000" + "0400" + "0000" + "1800" + "04000000" +
        "5778597a" + "00000000" + "22222222"
    static final String TWO_CTX_HEX = CTX0 + CTX1   // 60 bytes

    private static String hex(byte[] b) { ByteArrayUtils.toHex(b) }

    def "writeAll emits two chained contexts byte-exactly with padding and Next chaining"() {
        given:
        def buffer = new SMBBuffer()
        def contexts = [new SMB2CreateContext(NAME_A, DATA_A), new SMB2CreateContext(NAME_B, DATA_B)]

        when:
        int written = SMB2CreateContext.writeAll(buffer, contexts)

        then:
        hex(buffer.getCompactData()) == TWO_CTX_HEX
        written == 60
    }

    def "readAll round-trips the two-context bytes"() {
        given:
        def buffer = new SMBBuffer()
        buffer.putRawBytes(ByteArrayUtils.parseHex(TWO_CTX_HEX))

        when:
        def contexts = SMB2CreateContext.readAll(buffer, 0, 60)

        then:
        contexts.size() == 2
        hex(contexts[0].name) == "41624364"
        hex(contexts[0].data) == "1111111111111111"
        hex(contexts[1].name) == "5778597a"
        hex(contexts[1].data) == "22222222"
    }

    def "readAll(writeAll(x)) is the identity over names and data"() {
        given:
        def original = [new SMB2CreateContext(NAME_A, DATA_A), new SMB2CreateContext(NAME_B, DATA_B)]
        def writeBuf = new SMBBuffer()
        int written = SMB2CreateContext.writeAll(writeBuf, original)
        def readBuf = new SMBBuffer()
        readBuf.putRawBytes(writeBuf.getCompactData())

        when:
        def roundtripped = SMB2CreateContext.readAll(readBuf, 0, written)

        then:
        roundtripped.size() == original.size()
        [0, 1].every { hex(roundtripped[it].name) == hex(original[it].name) }
        [0, 1].every { hex(roundtripped[it].data) == hex(original[it].data) }
    }

    def "single context writes exactly 32 bytes with Next=0 and no trailing pad"() {
        given:
        def buffer = new SMBBuffer()

        when:
        int written = SMB2CreateContext.writeAll(buffer, [new SMB2CreateContext(NAME_A, DATA_A)])

        then:
        written == 32
        hex(buffer.getCompactData()) == CTX0.replaceFirst("20000000", "00000000") // same bytes, Next=0

        and:
        def back = SMB2CreateContext.readAll(new SMBBuffer().tap { putRawBytes(buffer.getCompactData()) }, 0, 32)
        back.size() == 1
        hex(back[0].name) == "41624364"
        hex(back[0].data) == "1111111111111111"
    }

    def "empty-data context sets DataOffset=0 / DataLength=0 and writes no data"() {
        given:
        def buffer = new SMBBuffer()

        when:
        int written = SMB2CreateContext.writeAll(buffer, [new SMB2CreateContext(NAME_A, new byte[0])])

        then:
        // header(16) + name(4) = 20 bytes, no data, no pad
        written == 20
        // Next=0, NameOffset=16, NameLen=4, Reserved=0, DataOffset=0, DataLen=0, name
        hex(buffer.getCompactData()) == "00000000" + "1000" + "0400" + "0000" + "0000" + "00000000" + "41624364"

        and:
        def back = SMB2CreateContext.readAll(new SMBBuffer().tap { putRawBytes(buffer.getCompactData()) }, 0, 20)
        back.size() == 1
        back[0].data.length == 0
    }

    def "empty / null list writes nothing and readAll(.,0,0) is empty"() {
        expect:
        SMB2CreateContext.writeAll(new SMBBuffer(), []) == 0
        SMB2CreateContext.writeAll(new SMBBuffer(), null) == 0
        new SMBBuffer().getCompactData().length == 0
        SMB2CreateContext.readAll(new SMBBuffer(), 0, 0).isEmpty()
    }

    def "Next chain is authoritative over an over-reported length"() {
        given:
        def buffer = new SMBBuffer()
        buffer.putRawBytes(ByteArrayUtils.parseHex(TWO_CTX_HEX))

        when: "caller over-reports length (64 > 60)"
        def contexts = SMB2CreateContext.readAll(buffer, 0, 64)

        then: "Next==0 still terminates at exactly two contexts"
        contexts.size() == 2
    }
}
