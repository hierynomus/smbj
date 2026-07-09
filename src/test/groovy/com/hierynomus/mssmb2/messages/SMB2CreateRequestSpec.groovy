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

import com.hierynomus.msdtyp.AccessMask
import com.hierynomus.msfscc.FileAttributes
import com.hierynomus.mssmb2.LeaseKey
import com.hierynomus.mssmb2.SMB2CreateDisposition
import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.mssmb2.SMB2ImpersonationLevel
import com.hierynomus.mssmb2.SMB2LeaseState
import com.hierynomus.mssmb2.SMB2OplockLevel
import com.hierynomus.mssmb2.SMB2ShareAccess
import com.hierynomus.mssmb2.messages.create.SMB2CreateContext
import com.hierynomus.mssmb2.messages.create.SMB2LeaseCreateContext
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.smb.SMBBuffer
import com.hierynomus.smbj.common.SmbPath
import spock.lang.Specification

class SMB2CreateRequestSpec extends Specification {
    static final LeaseKey KEY = new LeaseKey(ByteArrayUtils.parseHex("000102030405060708090a0b0c0d0e0f"))
    static final LeaseKey PARENT = new LeaseKey(ByteArrayUtils.parseHex("101112131415161718191a1b1c1d1e1f"))
    static final SmbPath ROOT = new SmbPath("HOST", "share")

    static byte[] writeReq(SMB2OplockLevel oplock, List<SMB2CreateContext> contexts) {
        def req = new SMB2CreateRequest(SMB2Dialect.SMB_3_1_1, 1L, 1L, SMB2ImpersonationLevel.Identification,
            EnumSet.of(AccessMask.FILE_READ_DATA), EnumSet.of(FileAttributes.FILE_ATTRIBUTE_DIRECTORY),
            EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ), SMB2CreateDisposition.FILE_OPEN,
            EnumSet.noneOf(com.hierynomus.mssmb2.SMB2CreateOptions), ROOT, oplock, contexts)
        def b = new SMBBuffer()
        req.write(b)
        return b.getCompactData()
    }

    static byte[] writeReqLegacy() {
        def req = new SMB2CreateRequest(SMB2Dialect.SMB_3_1_1, 1L, 1L, SMB2ImpersonationLevel.Identification,
            EnumSet.of(AccessMask.FILE_READ_DATA), EnumSet.of(FileAttributes.FILE_ATTRIBUTE_DIRECTORY),
            EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ), SMB2CreateDisposition.FILE_OPEN,
            EnumSet.noneOf(com.hierynomus.mssmb2.SMB2CreateOptions), ROOT)
        def b = new SMBBuffer()
        req.write(b)
        return b.getCompactData()
    }

    def "a root create with a lease context emits OplockLevel=LEASE and a correctly-located context block"() {
        given:
        def leaseCtx = SMB2LeaseCreateContext.v2(KEY, SMB2LeaseState.readHandle(), PARENT).toCreateContext()
        def expectedCtx = new SMBBuffer().tap { SMB2CreateContext.writeAll(it, [leaseCtx]) }.getCompactData()

        when:
        byte[] bytes = writeReq(SMB2OplockLevel.SMB2_OPLOCK_LEVEL_LEASE, [leaseCtx])
        def rb = new SMBBuffer(bytes)

        then: "RequestedOplockLevel byte (header 64 + body offset 3 = 67) is 0xFF"
        (bytes[67] & 0xFF) == 0xFF

        and: "CreateContextsOffset (abs 112) = 128, CreateContextsLength (abs 116) = 76"
        rb.rpos(112); rb.readUInt32() == 128L
        rb.rpos(116); rb.readUInt32() == 76L

        and: "the context block at offset 128 is the exact wrapped RqLs context"
        ByteArrayUtils.toHex(Arrays.copyOfRange(bytes, 128, 128 + 76)) == ByteArrayUtils.toHex(expectedCtx)

        and: "total length = header(64) + body(56) + name(1) + pad(7) + ctx(76)"
        bytes.length == 204
    }

    def "a no-context create is unchanged: OplockLevel=NONE, zero context offset/length"() {
        when:
        byte[] bytes = writeReq(SMB2OplockLevel.SMB2_OPLOCK_LEVEL_NONE, [])
        def rb = new SMBBuffer(bytes)

        then:
        (bytes[67] & 0xFF) == 0x00
        rb.rpos(112); rb.readUInt32() == 0L
        rb.rpos(116); rb.readUInt32() == 0L
        bytes.length == 121 // header(64) + body(56) + name(1), no contexts
    }

    def "the legacy 10-arg constructor is byte-identical to the new constructor with NONE + empty list"() {
        expect:
        ByteArrayUtils.toHex(writeReqLegacy()) ==
            ByteArrayUtils.toHex(writeReq(SMB2OplockLevel.SMB2_OPLOCK_LEVEL_NONE, []))
    }
}
