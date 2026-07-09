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
import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.smb.SMBBuffer
import spock.lang.Specification

class SMB2LeaseBreakSpec extends Specification {
    static final LeaseKey KEY = new LeaseKey(ByteArrayUtils.parseHex("000102030405060708090a0b0c0d0e0f"))

    // A full SMB2 message: 64-byte header (Command=0x12, MessageId=FF*8, Session/Tree=0) + 44-byte body.
    static byte[] notificationBytes(String flagsHex, String currentHex, String newHex, String epochHex) {
        def b = new SMBBuffer()
        // --- SMB2 header (64 bytes) ---
        b.putRawBytes(ByteArrayUtils.parseHex("fe534d42")) // ProtocolId
        b.putUInt16(64); b.putUInt16(0)                    // StructureSize, CreditCharge
        b.putUInt32(0)                                     // Status
        b.putUInt16(0x12); b.putUInt16(0)                  // Command=OPLOCK_BREAK, CreditRequest
        b.putUInt32(1)                                     // Flags = SERVER_TO_REDIR
        b.putUInt32(0)                                     // NextCommand
        b.putRawBytes(ByteArrayUtils.parseHex("ffffffffffffffff")) // MessageId = all-FF
        b.putUInt32(0); b.putUInt32(0)                     // Reserved, TreeId = 0
        b.putRawBytes(ByteArrayUtils.parseHex("0000000000000000")) // SessionId = 0
        b.putRawBytes(ByteArrayUtils.parseHex("00000000000000000000000000000000")) // Signature
        // --- Lease Break Notification body (44 bytes) ---
        b.putRawBytes(ByteArrayUtils.parseHex("2c00"))     // StructureSize = 44
        b.putRawBytes(ByteArrayUtils.parseHex(epochHex))   // NewEpoch (2)
        b.putRawBytes(ByteArrayUtils.parseHex(flagsHex))   // Flags (4)
        b.putRawBytes(KEY.getBytes())                      // LeaseKey (16)
        b.putRawBytes(ByteArrayUtils.parseHex(currentHex)) // CurrentLeaseState (4)
        b.putRawBytes(ByteArrayUtils.parseHex(newHex))     // NewLeaseState (4)
        b.putRawBytes(ByteArrayUtils.parseHex("000000000000000000000000")) // BreakReason+hints
        return b.getCompactData()
    }

    def "parses a 44-byte lease break notification (RH->R, ack required, epoch 6)"() {
        given:
        def data = new com.hierynomus.mssmb2.SMB2PacketData(notificationBytes("01000000", "03000000", "01000000", "0600"))

        when:
        def n = new SMB2LeaseBreakNotification().parse(data)

        then:
        n.getNewEpoch() == 6
        n.isAckRequired()
        n.getLeaseKey() == KEY
        n.getCurrentLeaseState() == 0x3L
        n.getNewLeaseState() == 0x1L
    }

    def "Flags=0 means no ack required (pure-read break)"() {
        given:
        def data = new com.hierynomus.mssmb2.SMB2PacketData(notificationBytes("00000000", "01000000", "00000000", "0700"))

        when:
        def n = new SMB2LeaseBreakNotification().parse(data)

        then:
        !n.isAckRequired()
        n.getNewLeaseState() == 0x0L
    }

    def "builds the exact 36-byte lease break acknowledgment body"() {
        given:
        def ack = new SMB2LeaseBreakAcknowledgment(SMB2Dialect.SMB_3_1_1, 0L, 0L, KEY, 0x1L)
        def buf = new SMBBuffer()

        when: "write() emits the 64-byte header then the 36-byte body"
        ack.write(buf)
        def all = buf.getCompactData()
        def body = ByteArrayUtils.toHex(Arrays.copyOfRange(all, 64, all.length))

        then:
        body ==
            "2400" +                          // StructureSize = 36
            "0000" +                          // Reserved
            "00000000" +                      // Flags
            "000102030405060708090a0b0c0d0e0f" + // LeaseKey
            "01000000" +                      // LeaseState = R (subset of NewLeaseState)
            "0000000000000000"                // LeaseDuration
        all.length == 100                     // header(64) + body(36)
    }

    def "parses a 36-byte lease break response"() {
        given: "a full SMB2 message: header (normal MessageId) + 36-byte response body"
        def b = new SMBBuffer()
        b.putRawBytes(ByteArrayUtils.parseHex("fe534d42"))
        b.putUInt16(64); b.putUInt16(0); b.putUInt32(0)
        b.putUInt16(0x12); b.putUInt16(0); b.putUInt32(1); b.putUInt32(0)
        b.putRawBytes(ByteArrayUtils.parseHex("0500000000000000")) // MessageId = 5 (normal)
        b.putUInt32(0); b.putUInt32(0)
        b.putRawBytes(ByteArrayUtils.parseHex("0000000000000000")) // SessionId
        b.putRawBytes(ByteArrayUtils.parseHex("00000000000000000000000000000000")) // Signature
        b.putRawBytes(ByteArrayUtils.parseHex("2400"))     // StructureSize 36
        b.putRawBytes(ByteArrayUtils.parseHex("0000"))     // Reserved
        b.putRawBytes(ByteArrayUtils.parseHex("00000000")) // Flags
        b.putRawBytes(KEY.getBytes())
        b.putRawBytes(ByteArrayUtils.parseHex("01000000")) // LeaseState R
        b.putRawBytes(ByteArrayUtils.parseHex("0000000000000000"))
        def data = new com.hierynomus.mssmb2.SMB2PacketData(b.getCompactData())

        when:
        def resp = new SMB2LeaseBreakResponse().parse(data)

        then:
        resp.getLeaseKey() == KEY
        resp.getLeaseState() == 0x1L
    }
}
