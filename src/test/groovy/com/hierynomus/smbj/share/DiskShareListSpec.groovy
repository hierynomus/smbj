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
import com.hierynomus.msfscc.FileAttributes
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation
import com.hierynomus.mserref.NtStatus
import com.hierynomus.mssmb2.*
import com.hierynomus.mssmb2.messages.*
import com.hierynomus.mssmb2.messages.create.SMB2CreateContext
import com.hierynomus.mssmb2.messages.create.SMB2LeaseCreateContext
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.smb.SMBBuffer
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.connection.LeaseEntry
import com.hierynomus.smbj.testing.PacketProcessor
import com.hierynomus.smbj.testing.PacketProcessor.DefaultPacketProcessor
import com.hierynomus.smbj.testing.StubAuthenticator
import com.hierynomus.smbj.testing.StubTransportLayerFactory
import spock.lang.Specification
import spock.lang.Unroll

import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger

class DiskShareListSpec extends Specification {

    private Connection connection

    def cleanup() {
        connection?.close()
    }

    def "list on a leased directory that throws on enumeration closes the kept-open handle"() {
        given: "a server advertising SMB3 + DIRECTORY_LEASING that grants an RH lease on CREATE"
        def closedFileIds = [] as List<SMB2FileId>

        def processor = new DefaultPacketProcessor().wrap({ SMB2Packet req ->
            req = req.getPacket()
            if (req instanceof SMB2NegotiateRequest) {
                return buildNegotiateResponse()
            }
            if (req instanceof SMB2CreateRequest) {
                return buildLeasedCreateResponse()
            }
            if (req instanceof SMB2QueryDirectoryRequest) {
                // Fail the QUERY_DIRECTORY so list() throws
                def resp = new SMB2QueryDirectoryResponse()
                resp.header.statusCode = NtStatus.STATUS_ACCESS_DENIED.value
                return resp
            }
            if (req instanceof SMB2Close) {
                closedFileIds << req.getFileId()
                def resp = new SMB2Close()
                resp.header.statusCode = NtStatus.STATUS_SUCCESS.value
                return resp
            }
            null // DefaultPacketProcessor handles SESSION_SETUP, TREE_CONNECT, etc.
        })

        def config = SmbConfig.builder()
            .withDirectoryLeasingEnabled(true)
            .withDfsEnabled(false)
            .withTransportLayerFactory(new StubTransportLayerFactory(processor))
            .withAuthenticators(new StubAuthenticator.Factory())
            .build()

        def client = new SMBClient(config)
        connection = client.connect("127.0.0.1")
        def session = connection.authenticate(new AuthenticationContext("user", "pass".toCharArray(), "domain"))
        def share = session.connectShare("share") as DiskShare

        when: "list() is called on a path that would get an RH lease but fails on enumeration"
        share.list("testdir")

        then: "the exception propagates to the caller"
        thrown(SMBApiException)

        and: "the kept-open leased handle was closed (our fix: catch block calls closeSilently)"
        closedFileIds.size() > 0
    }

    def "list with existing RH lease but null cacheDirectory closes the re-opened handle on failure"() {
        given: "a server that grants an RH lease on CREATE but fails QUERY_DIRECTORY"
        def closedFileIds = [] as List<SMB2FileId>

        def processor = new DefaultPacketProcessor().wrap({ SMB2Packet req ->
            req = req.getPacket()
            if (req instanceof SMB2NegotiateRequest) {
                return buildNegotiateResponse()
            }
            if (req instanceof SMB2CreateRequest) {
                return buildLeasedCreateResponse()
            }
            if (req instanceof SMB2QueryDirectoryRequest) {
                def resp = new SMB2QueryDirectoryResponse()
                resp.header.statusCode = NtStatus.STATUS_ACCESS_DENIED.value
                return resp
            }
            if (req instanceof SMB2Close) {
                closedFileIds << req.getFileId()
                def resp = new SMB2Close()
                resp.header.statusCode = NtStatus.STATUS_SUCCESS.value
                return resp
            }
            null
        })

        def config = SmbConfig.builder()
            .withDirectoryLeasingEnabled(true)
            .withDfsEnabled(false)
            .withTransportLayerFactory(new StubTransportLayerFactory(processor))
            .withAuthenticators(new StubAuthenticator.Factory())
            .build()

        def client = new SMBClient(config)
        connection = client.connect("127.0.0.1")
        def session = connection.authenticate(new AuthenticationContext("user", "pass".toCharArray(), "domain"))
        def share = session.connectShare("share") as DiskShare

        // Pre-seed the LeaseManager with a valid RH entry for "testdir" but no cacheDirectory.
        // This forces list() into the existing-lease path with no retained cache handle.
        def lm = connection.getLeaseManager()
        def key = lm.leaseKeyForPath("share", "testdir")
        def seededEntry = new LeaseEntry(key, null, SMB2LeaseState.readHandle(), "share", "testdir")
        seededEntry.setOwner(session, share.treeConnect.treeId, SMB2Dialect.SMB_3_0)
        seededEntry.setGranted(true)
        seededEntry.setGrantedState(SMB2LeaseState.readHandle())
        lm.register(seededEntry)

        when:
        share.list("testdir")

        then: "the exception propagates"
        thrown(SMBApiException)

        and: "the re-opened handle was closed"
        closedFileIds.size() > 0

        cleanup:
        connection.close()
    }

    def "local write operations invalidate parent directory cache"() {
        given: "a server with directory leasing"
        def queryCount = new AtomicInteger(0)

        def processor = new DefaultPacketProcessor().wrap({ SMB2Packet req ->
            req = req.getPacket()
            if (req instanceof SMB2NegotiateRequest) {
                return buildNegotiateResponse()
            }
            if (req instanceof SMB2CreateRequest) {
                String p = req.path?.path ?: ""
                if (p == "parent") {
                    return buildLeasedCreateResponse(SMB2CreateAction.FILE_OPENED)
                }
                if (p.contains("newdir")) {
                    return buildLeasedCreateResponse(SMB2CreateAction.FILE_CREATED)
                }
                if (p.contains("newfile")) {
                    def resp = new SMB2CreateResponse()
                    resp.header.statusCode = NtStatus.STATUS_SUCCESS.value
                    resp.fileId = new SMB2FileId(new byte[8], new byte[8])
                    resp.fileAttributes = EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL)
                    resp.@createAction = SMB2CreateAction.FILE_CREATED
                    return resp
                }
                def resp = new SMB2CreateResponse()
                resp.header.statusCode = NtStatus.STATUS_SUCCESS.value
                resp.fileId = new SMB2FileId(new byte[8], new byte[8])
                resp.fileAttributes = EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL)
                resp.@createAction = SMB2CreateAction.FILE_OPENED
                return resp
            }
            if (req instanceof SMB2QueryDirectoryRequest) {
                if (req.flags.contains(SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags.SMB2_RESTART_SCANS)) {
                    queryCount.incrementAndGet()
                    return buildQueryDirectoryResponse()
                } else {
                    def resp = new SMB2QueryDirectoryResponse()
                    resp.header.statusCode = NtStatus.STATUS_NO_MORE_FILES.value
                    return resp
                }
            }
            if (req instanceof SMB2SetInfoRequest) {
                def resp = new SMB2SetInfoResponse()
                resp.header.statusCode = NtStatus.STATUS_SUCCESS.value
                return resp
            }
            if (req instanceof SMB2Close) {
                def resp = new SMB2Close()
                resp.header.statusCode = NtStatus.STATUS_SUCCESS.value
                return resp
            }
            null
        })

        def config = SmbConfig.builder()
            .withDirectoryLeasingEnabled(true)
            .withDfsEnabled(false)
            .withTransportLayerFactory(new StubTransportLayerFactory(processor))
            .withAuthenticators(new StubAuthenticator.Factory())
            .build()

        def client = new SMBClient(config)
        connection = client.connect("127.0.0.1")
        def session = connection.authenticate(new AuthenticationContext("user", "pass".toCharArray(), "domain"))
        def share = session.connectShare("share") as DiskShare

        when: "first list('parent') is called"
        def list1 = share.list("parent")

        then: "server was queried and result is returned"
        list1.size() > 0
        queryCount.get() == 1

        when: "the caller edits the first listing and repeats list('parent')"
        list1.clear()
        def list2 = share.list("parent")

        then: "the cached snapshot is unaffected and no new server query is made"
        list1.empty
        list2.size() == 1
        queryCount.get() == 1

        when: "mkdir under 'parent' is executed"
        share.mkdir("parent\\newdir")

        then: "parent cache was invalidated, so list('parent') queries server again"
        share.list("parent").size() > 0
        queryCount.get() == 2

        when: "repeat list('parent') is called after re-populating"
        share.list("parent")

        then: "served from cache again"
        queryCount.get() == 2

        when: "rm file under 'parent' is executed"
        share.rm("parent\\file.txt")

        then: "parent cache was invalidated, list('parent') queries server again"
        share.list("parent").size() > 0
        queryCount.get() == 3

        when: "openFile creating new file under 'parent' is executed"
        def f = share.openFile("parent\\newfile.txt", EnumSet.of(AccessMask.FILE_WRITE_DATA), null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null)
        f.close()

        then: "parent cache was invalidated, list('parent') queries server again"
        share.list("parent").size() > 0
        queryCount.get() == 4

        when: "rename file under 'parent' to another path"
        def fSrc = share.openFile("parent\\file.txt", EnumSet.of(AccessMask.GENERIC_ALL), null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)
        fSrc.rename("parent\\renamed.txt")
        fSrc.close()

        then: "parent cache was invalidated by rename, list('parent') queries server again"
        share.list("parent").size() > 0
        queryCount.get() == 5

        when: "rmdir under 'parent' is executed"
        share.rmdir("parent\\newdir", false)

        then: "parent cache was invalidated by rmdir, list('parent') queries server again"
        share.list("parent").size() > 0
        queryCount.get() == 6
    }

    @Unroll
    def "#change during #handleState enumeration prevents stale cache publication"() {
        given:
        def queryCount = new AtomicInteger()
        def closeCount = new AtomicInteger()
        boolean failClosedOnce = false
        Closure duringQuery = null
        def processor = new DefaultPacketProcessor().wrap({ SMB2Packet req ->
            req = req.packet
            if (req instanceof SMB2NegotiateRequest) {
                return buildNegotiateResponse()
            }
            if (req instanceof SMB2CreateRequest) {
                return buildLeasedCreateResponse()
            }
            if (req instanceof SMB2QueryDirectoryRequest) {
                if (req.flags.contains(SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags.SMB2_RESTART_SCANS)) {
                    queryCount.incrementAndGet()
                    if (failClosedOnce) {
                        failClosedOnce = false
                        def response = new SMB2QueryDirectoryResponse()
                        response.header.statusCode = NtStatus.STATUS_FILE_CLOSED.value
                        return response
                    }
                    // Interleave the mutation after QUERY_DIRECTORY starts and before its result
                    // reaches list(), without relying on thread timing.
                    def action = duringQuery
                    duringQuery = null
                    action?.call()
                    return buildQueryDirectoryResponse()
                }
                def response = new SMB2QueryDirectoryResponse()
                response.header.statusCode = NtStatus.STATUS_NO_MORE_FILES.value
                return response
            }
            if (req instanceof SMB2Close) {
                closeCount.incrementAndGet()
                def response = new SMB2Close()
                response.header.statusCode = NtStatus.STATUS_SUCCESS.value
                return response
            }
            null
        })
        def share = connectLeasingShare(processor)
        def manager = connection.leaseManager
        if (handleState != "first open") {
            share.list("parent")
            def entry = manager.getByPath("share", "parent")
            if (handleState == "reopened handle") {
                entry.invalidateCache()
            } else {
                entry.cache.invalidateAll() // Force a miss while keeping the existing handle.
                failClosedOnce = handleState == "server-closed handle"
            }
        }
        LeaseEntry queriedEntry = null
        long previousPopulates = 0
        duringQuery = {
            queriedEntry = manager.getByPath("share", "parent")
            previousPopulates = queriedEntry.cache.populates
            switch (change) {
                case "invalidation":
                    manager.invalidateDirectoryCache("share", "parent")
                    break
                case "lease break":
                    queriedEntry.broken = true
                    break
                case "lease downgrade":
                    queriedEntry.grantedState = SMB2LeaseState.SMB2_LEASE_READ_CACHING.value
                    break
            }
        }

        when:
        def result = share.list("parent")

        then: "the caller may receive the in-flight result, but the lease does not cache it"
        result.size() == 1
        queriedEntry != null
        queriedEntry.cache.populates == previousPopulates
        queriedEntry.cache.serve("share", "parent", FileIdBothDirectoryInformation, null) == null
        manager.getByPath("share", "parent")?.cache?.serve("share", "parent", FileIdBothDirectoryInformation, null) == null
        queriedEntry.cacheDirectory == null
        closeCount.get() > 0

        when: "the next listing must reach the server before it can be cached"
        int queriesBefore = queryCount.get()
        share.list("parent")

        then:
        queryCount.get() == queriesBefore + 1

        where:
        handleState            | change
        "first open"           | "invalidation"
        "existing handle"      | "invalidation"
        "reopened handle"      | "invalidation"
        "server-closed handle" | "invalidation"
        "first open"           | "lease break"
        "existing handle"      | "lease downgrade"
    }

    def "a reopened handle without a granted lease is closed after a successful listing"() {
        given:
        def closedFileIds = []
        def processor = new DefaultPacketProcessor().wrap({ SMB2Packet req ->
            req = req.packet
            if (req instanceof SMB2NegotiateRequest) {
                return buildNegotiateResponse()
            }
            if (req instanceof SMB2CreateRequest) {
                def response = buildLeasedCreateResponse()
                response.oplockLevel = SMB2OplockLevel.SMB2_OPLOCK_LEVEL_NONE
                response.createContexts = []
                return response
            }
            if (req instanceof SMB2QueryDirectoryRequest) {
                def response = new SMB2QueryDirectoryResponse()
                response.header.statusCode = NtStatus.STATUS_NO_MORE_FILES.value
                return response
            }
            if (req instanceof SMB2Close) {
                closedFileIds << req.fileId
                def response = new SMB2Close()
                response.header.statusCode = NtStatus.STATUS_SUCCESS.value
                return response
            }
            null
        })
        def share = connectLeasingShare(processor)
        def manager = connection.leaseManager
        def entry = new LeaseEntry(manager.leaseKeyForPath("share", "parent"), null,
            SMB2LeaseState.readHandle(), "share", "parent")
        entry.setOwner(share.session, share.treeConnect.treeId, SMB2Dialect.SMB_3_0)
        entry.granted = true
        entry.grantedState = SMB2LeaseState.readHandle()
        manager.register(entry)

        when:
        def result = share.list("parent")

        then:
        result.empty
        closedFileIds.size() == 1
        entry.cacheDirectory == null
        entry.cache.populates == 0
    }

    def "list with a search pattern queries the server instead of reusing the full leased listing"() {
        given:
        def queryPatterns = []
        def processor = new DefaultPacketProcessor().wrap({ SMB2Packet req ->
            req = req.packet
            if (req instanceof SMB2NegotiateRequest) {
                return buildNegotiateResponse()
            }
            if (req instanceof SMB2CreateRequest) {
                return buildLeasedCreateResponse()
            }
            if (req instanceof SMB2QueryDirectoryRequest) {
                if (req.flags.contains(SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags.SMB2_RESTART_SCANS)) {
                    queryPatterns << req.searchPattern
                    if (req.searchPattern == "*") {
                        return buildQueryDirectoryResponse("image.png")
                    }
                }
                def response = new SMB2QueryDirectoryResponse()
                response.header.statusCode = NtStatus.STATUS_NO_MORE_FILES.value
                return response
            }
            if (req instanceof SMB2Close) {
                def response = new SMB2Close()
                response.header.statusCode = NtStatus.STATUS_SUCCESS.value
                return response
            }
            null
        })
        def share = connectLeasingShare(processor)

        when: "first list populates the leased cache"
        def first = share.list("parent")

        then:
        first*.fileName == ["image.png"]
        queryPatterns == ["*"]

        when: "list with a search pattern when cache exists"
        def filtered = share.list("parent", "*.txt")

        then: "the server's empty search result is returned"
        filtered.empty
        queryPatterns == ["*", "*.txt"]

        when: "the full listing is requested again"
        def repeated = share.list("parent")

        then: "the search did not replace the cached full listing"
        repeated*.fileName == ["image.png"]
        queryPatterns == ["*", "*.txt"]
    }

    // ---- helpers ----

    private DiskShare connectLeasingShare(PacketProcessor processor) {
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

    private static SMB2NegotiateResponse buildNegotiateResponse() {
        def resp = new SMB2NegotiateResponse()
        resp.header.statusCode = NtStatus.STATUS_SUCCESS.value
        resp.dialect = SMB2Dialect.SMB_3_0
        resp.systemTime = FileTime.now()
        resp.serverGuid = UUID.randomUUID()
        // Advertise both LEASING and DIRECTORY_LEASING so supportsDirectoryLeasing() returns true
        resp.capabilities = EnumSet.of(
            SMB2GlobalCapability.SMB2_GLOBAL_CAP_LEASING,
            SMB2GlobalCapability.SMB2_GLOBAL_CAP_DIRECTORY_LEASING)
        return resp
    }

    private static SMB2CreateResponse buildLeasedCreateResponse(SMB2CreateAction action = SMB2CreateAction.FILE_OPENED) {
        def key = com.hierynomus.mssmb2.LeaseKey.random()

        // Build the V2 RqLs response data (52 bytes) inline
        def data = new SMBBuffer()
        data.putRawBytes(key.getBytes())                              // LeaseKey (16)
        data.putUInt32(SMB2LeaseState.readHandle())                   // LeaseState = RH (0x03)
        data.putUInt32(0)                                             // Flags
        data.putRawBytes(new byte[8])                                 // LeaseDuration
        data.putRawBytes(new byte[16])                                // ParentLeaseKey
        data.putUInt16(1)                                             // Epoch
        data.putUInt16(0)                                             // Reserved
        def leaseCtx = new SMB2CreateContext(SMB2LeaseCreateContext.NAME, data.getCompactData())

        def resp = new SMB2CreateResponse()
        resp.header.statusCode = NtStatus.STATUS_SUCCESS.value
        resp.fileId = new SMB2FileId(new byte[8], new byte[8])
        resp.fileAttributes = EnumSet.of(FileAttributes.FILE_ATTRIBUTE_DIRECTORY)
        resp.oplockLevel = SMB2OplockLevel.SMB2_OPLOCK_LEVEL_LEASE
        resp.createContexts = [leaseCtx]
        resp.@createAction = action
        return resp
    }

    private static SMB2QueryDirectoryResponse buildQueryDirectoryResponse(String fileName = ".") {
        def smbBuffer = new SMBBuffer()
        // 64 bytes SMB2 header (QUERY_DIRECTORY response)
        smbBuffer.putRawBytes(ByteArrayUtils.parseHex("fe534d4240000000000000000e000100010000000000000005000000000000000000000001000000010400d40058000000000000000000000000000000000000"))
        // SMB2 QUERY_DIRECTORY response body:
        smbBuffer.putUInt16(9) // StructureSize
        smbBuffer.putUInt16(72) // OutputBufferOffset (64 + 8 = 72)

        // Single FileIdBothDirectoryInformation entry.
        byte[] fileNameBytes = fileName.getBytes("UTF-16LE")
        def entryBuf = new SMBBuffer()
        entryBuf.putUInt32(0) // NextEntryOffset = 0 (only 1 entry)
        entryBuf.putUInt32(0) // FileIndex
        entryBuf.putRawBytes(new byte[32]) // 4 FileTimes
        entryBuf.putRawBytes(new byte[8]) // EndOfFile
        entryBuf.putRawBytes(new byte[8]) // AllocationSize
        entryBuf.putUInt32(fileName == "." ? 0x10 : 0x80) // FileAttributes
        entryBuf.putUInt32(fileNameBytes.length) // FileNameLength
        entryBuf.putUInt32(0) // EaSize
        entryBuf.putByte((byte) 0) // ShortNameLength
        entryBuf.putByte((byte) 0) // Reserved
        entryBuf.putRawBytes(new byte[24]) // ShortName (12 UTF-16 chars)
        entryBuf.putUInt16(0) // Reserved2 (2 bytes)
        entryBuf.putRawBytes(new byte[8]) // FileId
        entryBuf.putRawBytes(fileNameBytes)

        byte[] entryBytes = entryBuf.getCompactData()
        smbBuffer.putUInt32(entryBytes.length) // OutputBufferLength
        smbBuffer.putRawBytes(entryBytes) // The outputBuffer bytes

        return new SMB2MessageConverter().readPacket(null, new SMB2PacketData(smbBuffer.getCompactData())) as SMB2QueryDirectoryResponse
    }
}
