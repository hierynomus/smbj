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

import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation
import com.hierynomus.mssmb2.LeaseKey
import com.hierynomus.mssmb2.SMB2LeaseState
import com.hierynomus.smbj.share.Directory
import spock.lang.Specification

import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class LeaseEntrySpec extends Specification {
    def "invalidation publishes the eviction before network close and releases the entry monitor"() {
        given:
        def entry = new LeaseEntry(LeaseKey.random(), null, SMB2LeaseState.readHandle(), "share", "docs")
        def oldDirectory = Mock(Directory)
        def newDirectory = Mock(Directory)
        entry.setCacheDirectory(oldDirectory)
        entry.getCache().populate("share", "docs", FileIdBothDirectoryInformation, null, [])
        def closeStarted = new CountDownLatch(1)
        def finishClose = new CountDownLatch(1)
        def closeHeldMonitor = new AtomicBoolean(true)
        def oldCloseCount = new AtomicInteger()
        def newCloseCount = new AtomicInteger()
        def executor = Executors.newFixedThreadPool(2)
        oldDirectory.closeSilently() >> {
            oldCloseCount.incrementAndGet()
            closeHeldMonitor.set(Thread.holdsLock(entry))
            closeStarted.countDown()
            assert finishClose.await(10, TimeUnit.SECONDS)
        }
        newDirectory.closeSilently() >> { newCloseCount.incrementAndGet() }

        when: "the detached handle's network close remains blocked"
        def invalidation = executor.submit({ entry.invalidateCache() } as Callable<Integer>)

        then:
        closeStarted.await(5, TimeUnit.SECONDS)
        oldCloseCount.get() == 1
        !invalidation.isDone()
        !closeHeldMonitor.get()
        entry.getCacheGeneration() == 1
        entry.getCacheDirectory() == null
        entry.getCache().serve("share", "docs", FileIdBothDirectoryInformation, null) == null

        when: "another query installs a replacement while the old close is still blocked"
        def replacement = executor.submit({
            entry.setCacheDirectory(newDirectory)
            entry.clearCacheDirectory(oldDirectory)
            return entry.getCacheDirectory()
        } as Callable<Directory>)

        then: "entry operations can acquire the monitor and stale cleanup keeps the replacement"
        replacement.get(5, TimeUnit.SECONDS).is(newDirectory)

        when:
        finishClose.countDown()

        then: "completion of the old close also leaves the replacement installed"
        invalidation.get(5, TimeUnit.SECONDS) == 1
        entry.getCacheDirectory().is(newDirectory)
        newCloseCount.get() == 0

        cleanup:
        finishClose.countDown()
        executor.shutdownNow()
    }

    def "invalidations without a retained handle still advance the generation"() {
        given:
        def entry = new LeaseEntry(LeaseKey.random(), null, SMB2LeaseState.readHandle(), "docs")

        when:
        def first = entry.invalidateCache()
        def second = entry.invalidateCache()

        then:
        first == 1
        second == 2
        entry.getCacheGeneration() == 2
    }
}
