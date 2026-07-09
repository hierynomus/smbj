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
package com.hierynomus.smbj.connection

import com.hierynomus.mssmb2.LeaseKey
import com.hierynomus.mssmb2.SMB2LeaseState
import com.hierynomus.mssmb2.SMB2PacketData
import com.hierynomus.mssmb2.messages.SMB2LeaseBreakNotification
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.smb.SMBBuffer
import com.hierynomus.smbj.common.SmbPath
import spock.lang.Specification
import spock.lang.Unroll

class LeaseManagerSpec extends Specification {
    static final long RH = SMB2LeaseState.readHandle()

    static SMB2LeaseBreakNotification notification(LeaseKey key, int epoch, String flagsHex, long newState) {
        def b = new SMBBuffer()
        b.putRawBytes(ByteArrayUtils.parseHex("fe534d42"))
        b.putUInt16(64); b.putUInt16(0); b.putUInt32(0)
        b.putUInt16(0x12); b.putUInt16(0); b.putUInt32(1); b.putUInt32(0)
        b.putRawBytes(ByteArrayUtils.parseHex("ffffffffffffffff"))
        b.putUInt32(0); b.putUInt32(0)
        b.putRawBytes(ByteArrayUtils.parseHex("0000000000000000"))
        b.putRawBytes(ByteArrayUtils.parseHex("00000000000000000000000000000000"))
        b.putUInt16(44); b.putUInt16(epoch)
        b.putRawBytes(ByteArrayUtils.parseHex(flagsHex))
        b.putRawBytes(key.getBytes())
        b.putUInt32(RH); b.putUInt32(newState)
        b.putRawBytes(ByteArrayUtils.parseHex("000000000000000000000000"))
        return new SMB2LeaseBreakNotification().parse(new SMB2PacketData(b.getCompactData()))
    }

    @Unroll
    def "epochDelta(#newE, #storedE) = #expected"() {
        expect:
        LeaseManager.epochDelta(newE, storedE) == expected
        where:
        newE | storedE | expected
        6    | 6       | 0      // equal -> ignore
        7    | 6       | 1      // newer -> apply
        6    | 5       | 1
        5    | 6       | -1     // stale/reordered -> ignore
        1    | 65535   | 2      // wrap (server newer)
    }

    def "onBreak applies a newer no-ack break: state updated, cache invalidated, broken"() {
        given:
        def lm = new LeaseManager()
        def key = lm.leaseKeyForPath("d")
        def entry = new LeaseEntry(key, null, RH, "d")
        entry.setEpoch(0)
        lm.register(entry)

        when: "RH -> R, Flags=0 (no ack required)"
        lm.onBreak(notification(key, 1, "00000000", SMB2LeaseState.SMB2_LEASE_READ_CACHING.value))

        then:
        entry.getGrantedState() == 0x1L
        entry.getEpoch() == 1
        entry.isBroken()
        entry.getCacheGeneration() == 1
        lm.getBreaksHandled() == 1
    }

    def "onBreak ignores a stale break (epoch not newer)"() {
        given:
        def lm = new LeaseManager()
        def key = lm.leaseKeyForPath("d")
        def entry = new LeaseEntry(key, null, RH, "d")
        entry.setEpoch(6)
        entry.setGrantedState(RH)
        lm.register(entry)

        when: "newEpoch 6 == stored 6 -> stale"
        lm.onBreak(notification(key, 6, "00000000", 0x0L))

        then:
        entry.getGrantedState() == RH  // unchanged
        !entry.isBroken()
        entry.getCacheGeneration() == 0
        lm.getBreaksHandled() == 0
    }

    def "onBreak ignores a break for an unknown key"() {
        given:
        def lm = new LeaseManager()

        when:
        lm.onBreak(notification(LeaseKey.random(), 1, "00000000", 0x1L))

        then:
        noExceptionThrown()
        lm.getBreaksHandled() == 0
    }

    def "register makes an entry resolvable by key immediately (register-before-send)"() {
        given:
        def lm = new LeaseManager()
        def key = lm.leaseKeyForPath("subdir")
        def entry = new LeaseEntry(key, null, RH, "subdir")

        when: "the entry is registered (simulating pre-send registration)"
        lm.register(entry)

        then: "a break arriving now would resolve to it"
        lm.lookup(key).is(entry)
    }

    def "a child's parent key is the parent directory's own lease key"() {
        given:
        def lm = new LeaseManager()
        def rootKey = lm.leaseKeyForPath("")          // root opened with a lease
        lm.register(new LeaseEntry(rootKey, null, RH, ""))

        when:
        def parentPath = new SmbPath("h", "s", "sub").getParent().getPath()
        def childParent = lm.leaseKeyForExistingPath(parentPath == null ? "" : parentPath)

        then:
        childParent == rootKey

        and: "an un-leased parent yields null"
        lm.leaseKeyForExistingPath("never-opened") == null
    }

    def "node key is case-insensitive, stable, and survives unregister"() {
        given:
        def lm = new LeaseManager()

        expect: "same normalized path -> same key"
        lm.leaseKeyForPath("dir") == lm.leaseKeyForPath("DIR")

        when:
        def k = lm.leaseKeyForPath("dir")
        lm.register(new LeaseEntry(k, null, RH, "dir"))
        lm.unregister(k)

        then: "the live entry is gone but the node key survives for re-open"
        lm.lookup(k) == null
        lm.leaseKeyForPath("dir") == k
    }
}
