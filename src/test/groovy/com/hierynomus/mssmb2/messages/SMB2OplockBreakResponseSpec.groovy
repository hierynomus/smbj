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

import com.hierynomus.mssmb2.LeaseKey
import com.hierynomus.mssmb2.SMB2OplockLevel
import com.hierynomus.mssmb2.SMB2PacketData
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.smb.SMBBuffer
import com.hierynomus.smbj.common.SMBRuntimeException
import spock.lang.Specification

class SMB2OplockBreakResponseSpec extends Specification {

    static final LeaseKey LEASE_KEY = new LeaseKey(ByteArrayUtils.parseHex("000102030405060708090a0b0c0d0e0f"))
    static final byte[] PERSISTENT = ByteArrayUtils.parseHex("0102030405060708")
    static final byte[] VOLATILE   = ByteArrayUtils.parseHex("090a0b0c0d0e0f10")

    /** Build a full 88-byte SMB2 message with a 24-byte file-oplock break response body. */
    static byte[] fileOplockResponseBytes(int oplockLevel) {
        def b = new SMBBuffer()
        putHeader(b)
        b.putRawBytes(ByteArrayUtils.parseHex("1800"))     // StructureSize = 24
        b.putByte((byte) oplockLevel)                      // OplockLevel
        b.putByte((byte) 0)                                // Reserved
        b.putRawBytes(ByteArrayUtils.parseHex("00000000")) // Reserved
        b.putRawBytes(PERSISTENT)                          // FileId.PersistentHandle (8 bytes)
        b.putRawBytes(VOLATILE)                            // FileId.VolatileHandle (8 bytes)
        b.getCompactData()
    }

    /** Build a full 100-byte SMB2 message with a 36-byte lease break response body. */
    static byte[] leaseBreakResponseBytes(long leaseState) {
        def b = new SMBBuffer()
        putHeader(b)
        b.putRawBytes(ByteArrayUtils.parseHex("2400"))     // StructureSize = 36
        b.putRawBytes(ByteArrayUtils.parseHex("0000"))     // Reserved
        b.putRawBytes(ByteArrayUtils.parseHex("00000000")) // Flags
        b.putRawBytes(LEASE_KEY.getBytes())                // LeaseKey (16 bytes)
        b.putUInt32(leaseState)                            // LeaseState
        b.putRawBytes(ByteArrayUtils.parseHex("0000000000000000")) // LeaseDuration
        b.getCompactData()
    }

    /** Build a message with an unexpected StructureSize. */
    static byte[] unknownStructureSizeBytes(int structureSize) {
        def b = new SMBBuffer()
        putHeader(b)
        b.putUInt16(structureSize)
        b.putRawBytes(new byte[structureSize - 2]) // pad to fill body
        b.getCompactData()
    }

    private static void putHeader(SMBBuffer b) {
        b.putRawBytes(ByteArrayUtils.parseHex("fe534d42"))              // ProtocolId
        b.putUInt16(64); b.putUInt16(0)                                 // StructureSize, CreditCharge
        b.putUInt32(0)                                                  // Status
        b.putUInt16(0x12); b.putUInt16(0)                               // Command = OPLOCK_BREAK, CreditResponse
        b.putUInt32(1); b.putUInt32(0)                                  // Flags, NextCommand
        b.putRawBytes(ByteArrayUtils.parseHex("0500000000000000"))      // MessageId = 5 (normal)
        b.putUInt32(0); b.putUInt32(0)                                  // Reserved, TreeId
        b.putRawBytes(ByteArrayUtils.parseHex("0000000000000000"))      // SessionId
        b.putRawBytes(new byte[16])                                     // Signature
    }

    def "parses a 24-byte file-oplock break response"() {
        given:
        def data = new SMB2PacketData(fileOplockResponseBytes(0x00))

        when:
        def resp = new SMB2OplockBreakResponse()
        resp.read(data)

        then:
        !resp.isLease()
        resp.oplockLevel == SMB2OplockLevel.SMB2_OPLOCK_LEVEL_NONE
        resp.fileId.persistentHandle == PERSISTENT
        resp.fileId.volatileHandle   == VOLATILE
    }

    def "parses a 36-byte lease break response"() {
        given:
        def data = new SMB2PacketData(leaseBreakResponseBytes(0x01L))

        when:
        def resp = new SMB2OplockBreakResponse()
        resp.read(data)

        then:
        resp.isLease()
        resp.leaseKey  == LEASE_KEY
        resp.leaseState == 0x01L
    }

    def "throws for an unexpected StructureSize"() {
        given:
        def data = new SMB2PacketData(unknownStructureSizeBytes(48))

        when:
        def resp = new SMB2OplockBreakResponse()
        resp.read(data)

        then:
        thrown(SMBRuntimeException)
    }
}
