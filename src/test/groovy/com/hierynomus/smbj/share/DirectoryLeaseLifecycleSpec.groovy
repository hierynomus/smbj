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
package com.hierynomus.smbj.share

import com.hierynomus.mserref.NtStatus
import com.hierynomus.mssmb2.SMB2FileId
import com.hierynomus.mssmb2.SMB2LeaseState
import com.hierynomus.mssmb2.messages.SMB2Close
import com.hierynomus.protocol.commons.concurrent.Futures
import com.hierynomus.smbj.common.SMBRuntimeException
import com.hierynomus.smbj.common.SmbPath
import com.hierynomus.smbj.connection.LeaseManager
import spock.lang.Specification
import spock.lang.Unroll
import spock.util.concurrent.PollingConditions

import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit

class DirectoryLeaseLifecycleSpec extends Specification {
    def manager = new LeaseManager()

    def cleanup() {
        manager.close()
    }

    def "synchronous directory close releases its reservation once and a failed close remains retryable"() {
        given:
        def entry = manager.acquire("share", "docs", null, SMB2LeaseState.readHandle())
        def share = Mock(DiskShare)
        def directory = new Directory(new SMB2FileId(), share, new SmbPath("host", "share", "docs"), entry)
        manager.invalidateDirectoryAndDescendants("share", "docs")

        when:
        directory.close()

        then:
        1 * share.closeFileId(_) >> { throw new SMBRuntimeException("temporary close failure") }
        thrown(SMBRuntimeException)
        manager.lookup(entry.leaseKey).is(entry)

        when:
        directory.close()
        directory.close()
        directory.closeNoWait()

        then:
        1 * share.closeFileId(_)
        0 * share.closeFileIdNoWait(_)
        manager.lookup(entry.leaseKey) == null
    }

    @Unroll
    def "an asynchronous close releases break routing only after #status confirms closure"() {
        given:
        def entry = manager.acquire("share", "docs", null, SMB2LeaseState.readHandle())
        def pendingClose = new CompletableFuture<SMB2Close>()
        def receiveStarted = new CountDownLatch(1)
        def share = asynchronousShare(pendingClose, receiveStarted)
        def directory = new Directory(new SMB2FileId(), share, new SmbPath("host", "share", "docs"), entry)
        manager.invalidateDirectoryAndDescendants("share", "docs")

        when:
        directory.closeNoWait()
        directory.closeNoWait()
        directory.close()

        then:
        1 * share.closeFileIdNoWait(_) >> pendingClose
        0 * share.closeFileId(_)
        receiveStarted.await(5, TimeUnit.SECONDS)
        manager.lookup(entry.leaseKey).is(entry)

        when:
        pendingClose.complete(closeResponse(status))

        then:
        new PollingConditions(timeout: 5).eventually {
            assert manager.lookup(entry.leaseKey) == null
        }

        when:
        directory.close()
        directory.closeNoWait()

        then:
        0 * share.closeFileId(_)
        0 * share.closeFileIdNoWait(_)

        where:
        status << [NtStatus.STATUS_SUCCESS, NtStatus.STATUS_FILE_CLOSED]
    }

    @Unroll
    def "an asynchronous close failure #failure retains routing and permits a retry"() {
        given:
        def entry = manager.acquire("share", "docs", null, SMB2LeaseState.readHandle())
        def pendingClose = new CompletableFuture<SMB2Close>()
        def receiveStarted = new CountDownLatch(1)
        def share = asynchronousShare(pendingClose, receiveStarted)
        def directory = new Directory(new SMB2FileId(), share, new SmbPath("host", "share", "docs"), entry)
        manager.invalidateDirectoryAndDescendants("share", "docs")

        when:
        directory.closeNoWait()

        then:
        receiveStarted.await(5, TimeUnit.SECONDS)
        manager.lookup(entry.leaseKey).is(entry)

        when:
        if (failure instanceof NtStatus) {
            pendingClose.complete(closeResponse(failure))
        } else {
            pendingClose.completeExceptionally(failure)
        }

        new PollingConditions(timeout: 5).eventually {
            directory.close()
            assert manager.lookup(entry.leaseKey) == null
        }

        then:
        1 * share.closeFileId(_) >> {
            assert manager.lookup(entry.leaseKey).is(entry)
        }

        where:
        failure << [NtStatus.STATUS_ACCESS_DENIED, new IOException("connection failed")]
    }

    private DiskShare asynchronousShare(Future<SMB2Close> pendingClose, CountDownLatch receiveStarted) {
        def share = Mock(DiskShare)
        share.closeFileIdNoWait(_) >> pendingClose
        share.receive(_, _) >> { Future<SMB2Close> response, long timeout ->
            receiveStarted.countDown()
            timeout > 0
                ? Futures.get(response, timeout, TimeUnit.MILLISECONDS, SMBRuntimeException.Wrapper)
                : Futures.get(response, SMBRuntimeException.Wrapper)
        }
        return share
    }

    private static SMB2Close closeResponse(NtStatus status) {
        def response = new SMB2Close()
        response.header.statusCode = status.value
        return response
    }
}
