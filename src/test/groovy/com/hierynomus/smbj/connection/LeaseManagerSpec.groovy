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
import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.mssmb2.SMB2FileId
import com.hierynomus.mssmb2.SMB2LeaseState
import com.hierynomus.mssmb2.SMB2PacketData
import com.hierynomus.mssmb2.messages.SMB2LeaseBreakAcknowledgment
import com.hierynomus.mssmb2.messages.SMB2LeaseBreakNotification
import com.hierynomus.mssmb2.messages.SMB2Close
import com.hierynomus.mserref.NtStatus
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.smb.SMBBuffer
import com.hierynomus.smbj.common.SmbPath
import com.hierynomus.smbj.session.Session
import com.hierynomus.smbj.share.Directory
import com.hierynomus.smbj.share.DiskShare
import spock.lang.Specification
import spock.lang.Unroll
import spock.util.concurrent.PollingConditions

import java.util.concurrent.Callable
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

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

    def "onBreak marks the lease broken before closing and nulling the cache directory handle"() {
        given:
        def lm = new LeaseManager()
        def key = lm.leaseKeyForPath("d")
        def entry = new LeaseEntry(key, null, RH, "d")
        def dir = Mock(Directory)
        entry.setCacheDirectory(dir)
        lm.register(entry)

        when: "a no-ack break arrives"
        lm.onBreak(notification(key, 1, "00000000", SMB2LeaseState.SMB2_LEASE_READ_CACHING.value))

        then: "the cache directory handle is closed exactly once"
        1 * dir.closeNoWait() >> {
            assert entry.isBroken()
        }

        and: "the reference is cleared"
        entry.getCacheDirectory() == null
    }

    def "pending cache CLOSE does not block acknowledgments or subsequent lease breaks"() {
        given:
        def lm = new LeaseManager()
        def entry = lm.acquire("share", "docs", null, RH)
        def nextEntry = lm.acquire("share", "other", null, RH)
        def session = Mock(Session)
        entry.setOwner(session, 7L, SMB2Dialect.SMB_3_1_1)
        nextEntry.setOwner(session, 7L, SMB2Dialect.SMB_3_1_1)
        def pendingClose = new CompletableFuture<SMB2Close>()
        def closeSent = new CountDownLatch(1)
        def closeObserved = new CountDownLatch(1)
        def acknowledgments = new CountDownLatch(2)
        def share = Mock(DiskShare)
        share.closeFileIdNoWait(_) >> {
            closeSent.countDown()
            pendingClose
        }
        share.receive(pendingClose, 0L) >> {
            closeObserved.countDown()
            pendingClose.get()
        }
        // Model a server that cannot finish CLOSE until another lease break is handled.
        share.closeFileId(_) >> { pendingClose.get() }
        session.send(_ as SMB2LeaseBreakAcknowledgment) >> {
            assert closeSent.count == 0
            acknowledgments.countDown()
            null
        }
        entry.setCacheDirectory(new Directory(new SMB2FileId(), share,
            new SmbPath("host", "share", "docs"), entry))

        when:
        lm.dispatchBreak(notification(entry.leaseKey, 1, "01000000", 0x1L))
        lm.dispatchBreak(notification(nextEntry.leaseKey, 1, "01000000", 0x1L))

        then:
        acknowledgments.await(5, TimeUnit.SECONDS)
        closeObserved.await(5, TimeUnit.SECONDS)
        !pendingClose.done
        entry.getCacheDirectory() == null
        entry.getCacheGeneration() == 1
        lm.lookup(entry.leaseKey).is(entry)

        when:
        def closed = new SMB2Close()
        closed.header.statusCode = NtStatus.STATUS_SUCCESS.value
        pendingClose.complete(closed)

        then:
        new PollingConditions(timeout: 5).eventually {
            assert lm.lookup(entry.leaseKey) == null
        }

        cleanup:
        pendingClose.complete(new SMB2Close())
        lm.close()
    }

    def "close closes all kept-open cache directory handles before clearing the table"() {
        given:
        def lm = new LeaseManager()
        def key1 = lm.leaseKeyForPath("a")
        def key2 = lm.leaseKeyForPath("b")
        def entry1 = new LeaseEntry(key1, null, RH, "a")
        def entry2 = new LeaseEntry(key2, null, RH, "b")
        def dir1 = Mock(Directory)
        def dir2 = Mock(Directory)
        entry1.setCacheDirectory(dir1)
        entry2.setCacheDirectory(dir2)
        lm.register(entry1)
        lm.register(entry2)

        when:
        lm.close()

        then: "both cache handles are closed"
        1 * dir1.closeSilently()
        1 * dir2.closeSilently()

        and: "the tables are emptied"
        lm.lookup(key1) == null
        lm.lookup(key2) == null
    }

    def "different share names under same path yield distinct LeaseKey and LeaseEntry"() {
        given:
        def lm = new LeaseManager()

        when:
        def keyA = lm.leaseKeyForPath("shareA", "docs")
        def keyB = lm.leaseKeyForPath("shareB", "docs")

        then:
        keyA != keyB
        lm.leaseKeyForExistingPath("shareA", "docs") == keyA
        lm.leaseKeyForExistingPath("shareB", "docs") == keyB
        lm.leaseKeyForExistingPath("shareC", "docs") == null

        when:
        def entryA = new LeaseEntry(keyA, null, RH, "shareA", "docs")
        def entryB = new LeaseEntry(keyB, null, RH, "shareB", "docs")
        lm.register(entryA)
        lm.register(entryB)

        then:
        lm.getByPath("shareA", "docs").is(entryA)
        lm.getByPath("shareB", "docs").is(entryB)
        lm.getByPath("docs") == null
    }

    def "invalidateDirectoryCache invalidates only the specified share's directory cache and closes handle"() {
        given:
        def lm = new LeaseManager()
        def keyA = lm.leaseKeyForPath("shareA", "docs")
        def keyB = lm.leaseKeyForPath("shareB", "docs")
        def entryA = new LeaseEntry(keyA, null, RH, "shareA", "docs")
        def entryB = new LeaseEntry(keyB, null, RH, "shareB", "docs")
        def dirA = Mock(Directory)
        def dirB = Mock(Directory)
        entryA.setCacheDirectory(dirA)
        entryB.setCacheDirectory(dirB)
        lm.register(entryA)
        lm.register(entryB)

        when:
        lm.invalidateDirectoryCache("shareA", "docs")

        then: "entryA's cache handle is closed and generation bumped"
        1 * dirA.closeSilently()
        0 * dirB.closeSilently()
        entryA.getCacheDirectory() == null
        entryA.getCacheGeneration() == 1
        entryB.getCacheDirectory() != null
        entryB.getCacheGeneration() == 0
    }

    def "invalidateDirectoryAndDescendants detaches paths but preserves break routing in target share"() {
        given:
        def lm = new LeaseManager()
        def keyRoot = lm.leaseKeyForPath("shareA", "folder")
        def keySub1 = lm.leaseKeyForPath("shareA", "folder\\sub1")
        def keySub2 = lm.leaseKeyForPath("shareA", "folder\\sub1\\sub2")
        def keyOther = lm.leaseKeyForPath("shareA", "other")
        def keyShareB = lm.leaseKeyForPath("shareB", "folder")

        def entryRoot = new LeaseEntry(keyRoot, null, RH, "shareA", "folder")
        def entrySub1 = new LeaseEntry(keySub1, null, RH, "shareA", "folder\\sub1")
        def entrySub2 = new LeaseEntry(keySub2, null, RH, "shareA", "folder\\sub1\\sub2")
        def entryOther = new LeaseEntry(keyOther, null, RH, "shareA", "other")
        def entryShareB = new LeaseEntry(keyShareB, null, RH, "shareB", "folder")

        def dirRoot = Mock(Directory)
        def dirSub1 = Mock(Directory)
        def dirSub2 = Mock(Directory)
        def dirOther = Mock(Directory)
        def dirShareB = Mock(Directory)

        entryRoot.setCacheDirectory(dirRoot)
        entrySub1.setCacheDirectory(dirSub1)
        entrySub2.setCacheDirectory(dirSub2)
        entryOther.setCacheDirectory(dirOther)
        entryShareB.setCacheDirectory(dirShareB)

        lm.register(entryRoot)
        lm.register(entrySub1)
        lm.register(entrySub2)
        lm.register(entryOther)
        lm.register(entryShareB)

        when:
        lm.invalidateDirectoryAndDescendants("shareA", "\\FOLDER/")

        then: "folder and its descendants are closed and unmapped"
        1 * dirRoot.closeSilently()
        1 * dirSub1.closeSilently()
        1 * dirSub2.closeSilently()
        0 * dirOther.closeSilently()
        0 * dirShareB.closeSilently()

        lm.lookup(keyRoot).is(entryRoot)
        lm.lookup(keySub1).is(entrySub1)
        lm.lookup(keySub2).is(entrySub2)
        lm.lookup(keyOther).is(entryOther)
        lm.lookup(keyShareB).is(entryShareB)

        lm.getByPath("shareA", "folder") == null
        lm.getByPath("shareA", "folder\\sub1") == null
        lm.getByPath("shareA", "folder\\sub1\\sub2") == null
        lm.getByPath("shareA", "other").is(entryOther)
        lm.getByPath("shareB", "folder").is(entryShareB)
    }

    def "legacy path and share-qualified path occupy separate namespaces"() {
        given:
        def lm = new LeaseManager()
        def legacyKey = lm.leaseKeyForPath("shareA\\docs")
        def shareKey = lm.leaseKeyForPath("shareA", "docs")
        def legacyEntry = new LeaseEntry(legacyKey, null, RH, "shareA\\docs")
        def shareEntry = new LeaseEntry(shareKey, null, RH, "shareA", "docs")
        lm.register(legacyEntry)
        lm.register(shareEntry)

        expect:
        legacyKey != shareKey
        lm.leaseKeyForExistingPath("SHAREA/docs/") == legacyKey
        lm.leaseKeyForExistingPath("\\SHAREA\\", "DOCS/") == shareKey
        lm.getByPath("shareA\\docs").is(legacyEntry)
        lm.getByPath("shareA", "docs").is(shareEntry)

        when:
        lm.invalidateDirectoryAndDescendants("shareA\\docs")

        then:
        lm.leaseKeyForExistingPath("shareA\\docs") == null
        lm.getByPath("shareA", "docs").is(shareEntry)
        legacyEntry.getCacheGeneration() == 1
        shareEntry.getCacheGeneration() == 0

        cleanup:
        lm.close()
    }

    def "legacy root invalidation includes every legacy descendant and preserves share-qualified paths"() {
        given:
        def lm = new LeaseManager()
        def rootKey = lm.leaseKeyForPath("")
        def childKey = lm.leaseKeyForPath("docs\\child")
        def unusedKey = lm.leaseKeyForPath("unused")
        def shareKey = lm.leaseKeyForPath("shareA", "docs")
        def rootEntry = new LeaseEntry(rootKey, null, RH, "")
        def childEntry = new LeaseEntry(childKey, null, RH, "docs\\child")
        def shareEntry = new LeaseEntry(shareKey, null, RH, "shareA", "docs")
        lm.register(rootEntry)
        lm.register(childEntry)
        lm.register(shareEntry)

        when:
        lm.invalidateDirectoryAndDescendants(null, "")

        then:
        lm.leaseKeyForExistingPath("") == null
        lm.leaseKeyForExistingPath("docs\\child") == null
        lm.leaseKeyForExistingPath("unused") == null
        lm.leaseKeyForExistingPath("shareA", "docs") == shareKey
        lm.lookup(rootKey).is(rootEntry)
        lm.lookup(childKey).is(childEntry)
        lm.lookup(unusedKey) == null
        rootEntry.getCacheGeneration() == 1
        childEntry.getCacheGeneration() == 1
        shareEntry.getCacheGeneration() == 0

        cleanup:
        lm.close()
    }

    def "detached lease remains routable until every handle closes and cannot remove a reused path"() {
        given:
        def lm = new LeaseManager()
        def oldEntry = lm.acquire("share", "docs", null, RH)
        def secondHandle = lm.acquire("share", "DOCS/", null, RH)
        def session = Mock(Session)
        oldEntry.setOwner(session, 7L, SMB2Dialect.SMB_3_1_1)

        when:
        lm.invalidateDirectoryAndDescendants("share", "docs")
        def replacement = lm.acquire("share", "docs", null, RH)
        def reopened = lm.acquire("share", "docs", null, RH)
        lm.release(reopened)
        lm.release(oldEntry)
        lm.onBreak(notification(oldEntry.leaseKey, 1, "01000000", 0x1L))

        then:
        secondHandle.is(oldEntry)
        replacement.leaseKey != oldEntry.leaseKey
        reopened.is(replacement)
        lm.lookup(oldEntry.leaseKey).is(oldEntry)
        1 * session.send(_ as SMB2LeaseBreakAcknowledgment)

        when:
        lm.release(secondHandle)

        then:
        lm.lookup(oldEntry.leaseKey) == null
        lm.getByPath("share", "docs").is(replacement)

        when:
        lm.release(replacement)

        then:
        lm.lookup(replacement.leaseKey) == null
        lm.leaseKeyForExistingPath("share", "docs") == replacement.leaseKey

        cleanup:
        lm.close()
    }

    def "a broken lease gets a new key while its open handles keep their break route"() {
        given:
        def lm = new LeaseManager()
        def oldEntry = lm.acquire("share", "docs", null, RH)
        oldEntry.broken = true

        when:
        def replacement = lm.acquire("share", "docs", null, RH)
        def reopened = lm.acquire("share", "docs", null, RH)
        lm.release(reopened)

        then:
        replacement.leaseKey != oldEntry.leaseKey
        lm.lookup(oldEntry.leaseKey).is(oldEntry)
        lm.getByPath("share", "docs").is(replacement)
        reopened.is(replacement)

        when:
        lm.release(oldEntry)

        then:
        lm.lookup(oldEntry.leaseKey) == null
        lm.getByPath("share", "docs").is(replacement)

        cleanup:
        lm.release(replacement)
        lm.close()
    }

    def "cache close during detachment does not block acquisition of the replacement path"() {
        given:
        def lm = new LeaseManager()
        def oldEntry = lm.acquire("share", "docs", null, RH)
        def oldDirectory = Mock(Directory)
        oldEntry.setCacheDirectory(oldDirectory)
        def closeStarted = new CountDownLatch(1)
        def finishClose = new CountDownLatch(1)
        def executor = Executors.newFixedThreadPool(2)
        oldDirectory.closeSilently() >> {
            closeStarted.countDown()
            assert finishClose.await(10, TimeUnit.SECONDS)
        }

        when:
        def invalidation = executor.submit({ lm.invalidateDirectoryAndDescendants("share", "docs") } as Callable)

        then:
        closeStarted.await(5, TimeUnit.SECONDS)

        when:
        def acquisition = executor.submit({ lm.acquire("share", "docs", null, RH) } as Callable<LeaseEntry>)
        def replacement = acquisition.get(5, TimeUnit.SECONDS)

        then:
        !invalidation.done
        replacement.leaseKey != oldEntry.leaseKey
        lm.lookup(oldEntry.leaseKey).is(oldEntry)
        lm.getByPath("share", "docs").is(replacement)

        when:
        finishClose.countDown()
        invalidation.get(5, TimeUnit.SECONDS)
        lm.release(oldEntry)

        then:
        lm.lookup(oldEntry.leaseKey) == null
        lm.getByPath("share", "docs").is(replacement)

        cleanup:
        finishClose.countDown()
        executor.shutdownNow()
        lm.close()
    }

    def "queued close completions never wait on the submitting thread under load"() {
        given:
        def lm = new LeaseManager()
        def firstStarted = new CountDownLatch(1)
        def workersStarted = new CountDownLatch(8)
        def finishCompletions = new CountDownLatch(1)
        def extraCompleted = new CountDownLatch(1)
        def callerThread = new AtomicReference<Thread>()
        def completionThread = new AtomicReference<Thread>()
        def caller = Executors.newSingleThreadExecutor()
        def blockedCompletion = {
            firstStarted.countDown()
            workersStarted.countDown()
            finishCompletions.await()
        } as Runnable
        lm.dispatchClose(blockedCompletion)
        assert firstStarted.await(5, TimeUnit.SECONDS)
        // Occupy all workers and queue additional completions.
        263.times { lm.dispatchClose(blockedCompletion) }
        assert workersStarted.await(5, TimeUnit.SECONDS)

        when:
        def submission = caller.submit({
            callerThread.set(Thread.currentThread())
            lm.dispatchClose({
                completionThread.set(Thread.currentThread())
                finishCompletions.await()
                extraCompleted.countDown()
            } as Runnable)
        } as Callable)
        submission.get(5, TimeUnit.SECONDS)

        then: "submission returns while all response workers are still waiting"
        completionThread.get() == null

        when:
        finishCompletions.countDown()

        then:
        extraCompleted.await(5, TimeUnit.SECONDS)
        completionThread.get() != callerThread.get()

        cleanup:
        finishCompletions.countDown()
        caller.shutdownNow()
        lm.close()
    }
}
