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

import com.hierynomus.msdtyp.FileTime
import com.hierynomus.mserref.NtStatus
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation
import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.mssmb2.SMB2GlobalCapability
import com.hierynomus.mssmb2.SMB2LeaseState
import com.hierynomus.mssmb2.SMB2OplockLevel
import com.hierynomus.mssmb2.SMB2Packet
import com.hierynomus.mssmb2.SMBApiException
import com.hierynomus.mssmb2.messages.SMB2CreateRequest
import com.hierynomus.mssmb2.messages.SMB2CreateResponse
import com.hierynomus.mssmb2.messages.SMB2NegotiateRequest
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse
import com.hierynomus.mssmb2.messages.SMB2SessionSetup
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.connection.LeaseEntry
import com.hierynomus.smbj.testing.PacketProcessor.DefaultPacketProcessor
import com.hierynomus.smbj.testing.StubAuthenticator
import com.hierynomus.smbj.testing.StubTransportLayerFactory
import spock.lang.Specification
import spock.lang.Unroll

import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class DiskShareCacheHandleSpec extends Specification {
    private Connection connection

    def cleanup() {
        connection?.close()
    }

    def "concurrent cache misses complete one enumeration before restarting the same handle"() {
        given:
        def share = connectLeasingShare()
        def manager = connection.leaseManager
        def entry = new LeaseEntry(manager.leaseKeyForPath("share", "docs"), null,
            SMB2LeaseState.readHandle(), "share", "docs")
        entry.granted = true
        entry.grantedState = SMB2LeaseState.readHandle()
        entry.setOwner(share.session, share.treeConnect.treeId, share.treeConnect.negotiatedProtocol.dialect)
        manager.register(entry)
        def directory = Mock(Directory)
        entry.cacheDirectory = directory
        def firstEnumerationStarted = new CountDownLatch(1)
        def finishFirstEnumeration = new CountDownLatch(1)
        def secondHandleSelected = new CountDownLatch(1)
        def secondEnumerationStarted = new CountDownLatch(1)
        def selections = new AtomicInteger()
        def enumerations = new AtomicInteger()
        def executor = Executors.newFixedThreadPool(2)
        directory.getLeaseEntry() >> {
            if (selections.incrementAndGet() == 2) {
                secondHandleSelected.countDown()
            }
            entry
        }
        directory.list(FileIdBothDirectoryInformation, null) >> {
            if (enumerations.incrementAndGet() == 1) {
                firstEnumerationStarted.countDown()
                assert finishFirstEnumeration.await(10, TimeUnit.SECONDS)
            } else {
                secondEnumerationStarted.countDown()
            }
            []
        }

        when:
        def first = executor.submit({ share.list("docs") } as Callable<List>)
        assert firstEnumerationStarted.await(5, TimeUnit.SECONDS)
        def second = executor.submit({ share.list("docs") } as Callable<List>)
        assert secondHandleSelected.await(5, TimeUnit.SECONDS)

        then: "the second caller cannot restart the first caller's server-side cursor"
        !secondEnumerationStarted.await(200, TimeUnit.MILLISECONDS)

        when:
        finishFirstEnumeration.countDown()

        then:
        first.get(5, TimeUnit.SECONDS).empty
        second.get(5, TimeUnit.SECONDS).empty
        enumerations.get() == 2

        cleanup:
        finishFirstEnumeration.countDown()
        executor.shutdownNow()
    }

    def "a selected cache handle detached before enumeration cannot be reinstalled while its close is blocked"() {
        given:
        def share = connectLeasingShare()
        def manager = connection.leaseManager
        def entry = new LeaseEntry(manager.leaseKeyForPath("share", "docs"), null,
            SMB2LeaseState.readHandle(), "share", "docs")
        entry.granted = true
        entry.grantedState = SMB2LeaseState.readHandle()
        entry.setOwner(share.session, share.treeConnect.treeId, share.treeConnect.negotiatedProtocol.dialect)
        manager.register(entry)
        def directory = Mock(Directory)
        entry.cacheDirectory = directory
        def closeStarted = new CountDownLatch(1)
        def finishClose = new CountDownLatch(1)
        def closeCalls = new AtomicInteger()
        def executor = Executors.newSingleThreadExecutor()
        Future<Integer> invalidation = null
        directory.getLeaseEntry() >> {
            // list() has selected this handle, but its enumeration helper has not captured
            // the lease generation yet. Detach it and leave its network CLOSE in progress.
            invalidation = executor.submit({ entry.invalidateCache() } as Callable<Integer>)
            assert closeStarted.await(5, TimeUnit.SECONDS)
            return entry
        }
        directory.closeSilently() >> {
            if (closeCalls.incrementAndGet() == 1) {
                closeStarted.countDown()
                assert finishClose.await(10, TimeUnit.SECONDS)
            }
        }
        directory.list(FileIdBothDirectoryInformation, null) >> []

        when: "the query completes before the invalidation's CLOSE does"
        def result = share.list("docs")

        then: "the detached handle and its query results stay out of the cache"
        result.empty
        !invalidation.isDone()
        entry.cacheGeneration == 1
        entry.cacheDirectory == null
        entry.cache.populates == 0
        entry.cache.serve("share", "docs", FileIdBothDirectoryInformation, null) == null

        when:
        finishClose.countDown()

        then:
        invalidation.get(5, TimeUnit.SECONDS) == 1
        entry.cacheDirectory == null
        entry.cache.populates == 0

        cleanup:
        finishClose.countDown()
        executor.shutdownNow()
    }

    @Unroll
    def "another session cannot reuse a directory's #cachedState"() {
        given:
        def sessionIds = new AtomicInteger()
        def creates = []
        def ownerShare = connectLeasingShare { request ->
            if (request instanceof SMB2SessionSetup) {
                def response = new SMB2SessionSetup()
                response.header.statusCode = NtStatus.STATUS_SUCCESS.value
                response.header.sessionId = sessionIds.incrementAndGet()
                response.securityBuffer = new byte[16]
                response.sessionFlags = EnumSet.noneOf(SMB2SessionSetup.SMB2SessionFlags)
                return response
            }
            if (request instanceof SMB2CreateRequest) {
                creates << request
                def response = new SMB2CreateResponse()
                response.header.statusCode = NtStatus.STATUS_ACCESS_DENIED.value
                return response
            }
            null
        }
        def manager = connection.leaseManager
        def entry = new LeaseEntry(manager.leaseKeyForPath("share", "docs"), null,
            SMB2LeaseState.readHandle(), "share", "docs")
        entry.granted = true
        entry.grantedState = SMB2LeaseState.readHandle()
        entry.setOwner(ownerShare.session, ownerShare.treeConnect.treeId,
            ownerShare.treeConnect.negotiatedProtocol.dialect)
        manager.register(entry)
        def ownerDirectory = Mock(Directory)
        entry.cacheDirectory = ownerDirectory
        if (cachePopulated) {
            entry.cache.populate("share", "docs", FileIdBothDirectoryInformation, null, [])
        }
        def otherSession = connection.authenticate(new AuthenticationContext("other-user", "pass".toCharArray(), "domain"))
        def otherShare = otherSession.connectShare("share") as DiskShare
        assert otherSession.sessionId != ownerShare.session.sessionId

        when:
        otherShare.list("docs")

        then: "the server checks the caller's permissions on an ordinary CREATE"
        def failure = thrown(SMBApiException)
        failure.status == NtStatus.STATUS_ACCESS_DENIED
        creates.size() == 1
        creates[0].header.sessionId == otherSession.sessionId
        creates[0].requestedOplockLevel == SMB2OplockLevel.SMB2_OPLOCK_LEVEL_NONE
        creates[0].createContexts.empty
        0 * ownerDirectory.list(_, _)

        and: "the original session retains its lease, handle, and routing reservation"
        entry.session.is(ownerShare.session)
        entry.cacheDirectory.is(ownerDirectory)
        entry.handleReferences == 1
        entry.cacheGeneration == 0
        entry.cache.populates == (cachePopulated ? 1 : 0)
        manager.lookup(entry.leaseKey).is(entry)
        manager.getByPath("share", "docs").is(entry)

        where:
        cachePopulated | cachedState
        true           | "cached listing"
        false          | "dedicated handle"
    }

    private DiskShare connectLeasingShare(Closure<SMB2Packet> onRequest = { null }) {
        def processor = new DefaultPacketProcessor().wrap({ request ->
            request = request.packet
            if (request instanceof SMB2NegotiateRequest) {
                def response = new SMB2NegotiateResponse()
                response.header.statusCode = NtStatus.STATUS_SUCCESS.value
                response.dialect = SMB2Dialect.SMB_3_0
                response.systemTime = FileTime.now()
                response.serverGuid = UUID.randomUUID()
                response.capabilities = EnumSet.of(
                    SMB2GlobalCapability.SMB2_GLOBAL_CAP_LEASING,
                    SMB2GlobalCapability.SMB2_GLOBAL_CAP_DIRECTORY_LEASING)
                return response
            }
            onRequest.call(request)
        })
        def config = SmbConfig.builder()
            .withDirectoryLeasingEnabled(true)
            .withDfsEnabled(false)
            .withTransportLayerFactory(new StubTransportLayerFactory(processor))
            .withAuthenticators(new StubAuthenticator.Factory())
            .build()
        connection = new SMBClient(config).connect("127.0.0.1")
        def session = connection.authenticate(new AuthenticationContext("user", "pass".toCharArray(), "domain"))
        return session.connectShare("share") as DiskShare
    }
}
