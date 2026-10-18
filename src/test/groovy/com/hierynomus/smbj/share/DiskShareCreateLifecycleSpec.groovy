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

import com.hierynomus.msdtyp.AccessMask
import com.hierynomus.msdtyp.FileTime
import com.hierynomus.mserref.NtStatus
import com.hierynomus.msfscc.FileAttributes
import com.hierynomus.mssmb2.*
import com.hierynomus.mssmb2.messages.*
import com.hierynomus.mssmb2.messages.create.SMB2CreateContext
import com.hierynomus.mssmb2.messages.create.SMB2LeaseCreateContext
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

class DiskShareCreateLifecycleSpec extends Specification {
    private Connection connection
    private final List<SMB2FileId> closedIds = []
    private final List<SMB2LeaseBreakAcknowledgment> acknowledgments = []

    def cleanup() {
        connection?.close()
    }

    def "a detached pending CREATE keeps routing until its failed response releases the reservation"() {
        given:
        LeaseEntry pending = null
        def share = connectLeasingShare {
            def manager = connection.leaseManager
            pending = manager.getByPath("share", "docs")
            assert pending.handleReferences == 1
            manager.invalidateDirectoryAndDescendants("share", "docs")
            assert manager.getByPath("share", "docs") == null
            assert manager.lookup(pending.leaseKey).is(pending)
            return deniedCreate()
        }

        when:
        openDirectory(share)

        then:
        thrown(SMBApiException)
        pending != null
        pending.handleReferences == 0
        connection.leaseManager.lookup(pending.leaseKey) == null
        connection.leaseManager.leaseKeyForPath("share", "docs") != pending.leaseKey
        closedIds.empty
    }

    def "a lease break before CREATE completes is acknowledged and its state survives the older grant"() {
        given:
        LeaseEntry pending = null
        def share = connectLeasingShare {
            def manager = connection.leaseManager
            pending = manager.getByPath("share", "docs")
            def notification = Stub(SMB2LeaseBreakNotification) {
                getLeaseKey() >> pending.leaseKey
                getNewEpoch() >> 1
                getNewLeaseState() >> SMB2LeaseState.SMB2_LEASE_READ_CACHING.value
                isAckRequired() >> true
            }
            manager.onBreak(notification)
            return createResponse(fileId(1), [SMB2LeaseCreateContext.v2(pending.leaseKey,
                SMB2LeaseState.readHandle(), null).toCreateContext()])
        }

        when:
        def directory = openDirectory(share)

        then:
        acknowledgments.size() == 1
        directory.leaseEntry.is(pending)
        pending.granted
        pending.broken
        pending.epoch == 1
        pending.grantedState == SMB2LeaseState.SMB2_LEASE_READ_CACHING.value

        cleanup:
        directory?.close()
    }

    @Unroll
    def "a reused lease rolls back only the second CREATE reservation after #outcome"() {
        given:
        int creates = 0
        LeaseEntry sharedEntry = null
        def firstId = fileId(1)
        def secondId = fileId(2)
        def share = connectLeasingShare {
            def entry = connection.leaseManager.getByPath("share", "docs")
            if (++creates == 1) {
                sharedEntry = entry
                return createResponse(firstId, [SMB2LeaseCreateContext.v2(entry.leaseKey,
                    SMB2LeaseState.readHandle(), null).toCreateContext()])
            }
            assert entry.is(sharedEntry)
            assert entry.handleReferences == 2
            if (outcome == "denied") {
                return deniedCreate()
            }
            return createResponse(secondId, outcome == "malformed lease"
                ? [new SMB2CreateContext(SMB2LeaseCreateContext.NAME, new byte[1])] : [])
        }
        def first = openDirectory(share)
        Directory second = null
        Exception failure = null

        when:
        try {
            second = openDirectory(share)
        } catch (Exception caught) {
            failure = caught
        }

        then:
        failure?.class == expectedFailure
        (second != null) == (outcome == "no lease")
        second?.leaseEntry == null
        connection.leaseManager.lookup(sharedEntry.leaseKey).is(sharedEntry)
        connection.leaseManager.getByPath("share", "docs").is(sharedEntry)
        sharedEntry.handleReferences == 1
        sharedEntry.granted
        closedIds == (outcome == "malformed lease" ? [secondId] : [])

        when:
        second?.close()
        first.close()

        then:
        sharedEntry.handleReferences == 0
        connection.leaseManager.lookup(sharedEntry.leaseKey) == null
        closedIds.contains(firstId)

        where:
        outcome           | expectedFailure
        "denied"          | SMBApiException
        "no lease"        | null
        "malformed lease" | IllegalArgumentException
    }

    private DiskShare connectLeasingShare(Closure<SMB2CreateResponse> onCreate) {
        def processor = new DefaultPacketProcessor().wrap({ request ->
            request = request.packet
            if (request instanceof SMB2NegotiateRequest) {
                def response = new SMB2NegotiateResponse()
                response.header.statusCode = NtStatus.STATUS_SUCCESS.value
                response.dialect = SMB2Dialect.SMB_3_0
                response.systemTime = FileTime.now()
                response.serverGuid = UUID.randomUUID()
                response.capabilities = EnumSet.of(SMB2GlobalCapability.SMB2_GLOBAL_CAP_LEASING,
                    SMB2GlobalCapability.SMB2_GLOBAL_CAP_DIRECTORY_LEASING)
                return response
            }
            if (request instanceof SMB2CreateRequest) {
                return onCreate.call()
            }
            if (request instanceof SMB2LeaseBreakAcknowledgment) {
                acknowledgments << request
                def response = new SMB2Packet()
                response.header.messageType = SMB2MessageCommandCode.SMB2_OPLOCK_BREAK
                response.header.statusCode = NtStatus.STATUS_SUCCESS.value
                return response
            }
            if (request instanceof SMB2Close) {
                closedIds << request.fileId
                def response = new SMB2Close()
                response.header.statusCode = NtStatus.STATUS_SUCCESS.value
                return response
            }
            null
        })
        def config = SmbConfig.builder().withDirectoryLeasingEnabled(true).withDfsEnabled(false)
            .withTransportLayerFactory(new StubTransportLayerFactory(processor))
            .withAuthenticators(new StubAuthenticator.Factory()).build()
        connection = new SMBClient(config).connect("127.0.0.1")
        def session = connection.authenticate(new AuthenticationContext("user", "pass".toCharArray(), "domain"))
        return session.connectShare("share") as DiskShare
    }

    private static Directory openDirectory(DiskShare share) {
        return share.openDirectory("docs", EnumSet.of(AccessMask.FILE_LIST_DIRECTORY), null,
            SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)
    }

    private static SMB2CreateResponse deniedCreate() {
        def response = new SMB2CreateResponse()
        response.header.statusCode = NtStatus.STATUS_ACCESS_DENIED.value
        return response
    }

    private static SMB2CreateResponse createResponse(SMB2FileId id, List<SMB2CreateContext> contexts) {
        def response = new SMB2CreateResponse()
        response.header.statusCode = NtStatus.STATUS_SUCCESS.value
        response.fileId = id
        response.fileAttributes = EnumSet.of(FileAttributes.FILE_ATTRIBUTE_DIRECTORY)
        response.@createAction = SMB2CreateAction.FILE_OPENED
        response.oplockLevel = contexts.empty ? SMB2OplockLevel.SMB2_OPLOCK_LEVEL_NONE
            : SMB2OplockLevel.SMB2_OPLOCK_LEVEL_LEASE
        response.createContexts = contexts
        return response
    }

    private static SMB2FileId fileId(int id) {
        def volatileId = new byte[8]
        volatileId[0] = (byte) id
        return new SMB2FileId(new byte[8], volatileId)
    }
}
