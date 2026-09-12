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
import com.hierynomus.mserref.NtStatus
import com.hierynomus.mssmb2.*
import com.hierynomus.mssmb2.messages.*
import com.hierynomus.mssmb2.messages.create.SMB2CreateContext
import com.hierynomus.mssmb2.messages.create.SMB2LeaseCreateContext
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

import java.util.UUID

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
        // This forces list() into the existing-lease path → dir==null → openLeasedCacheHandleAndList.
        def lm = connection.getLeaseManager()
        def key = lm.leaseKeyForPath("testdir")
        def seededEntry = new LeaseEntry(key, null, SMB2LeaseState.readHandle(), "testdir")
        seededEntry.setGranted(true)
        seededEntry.setGrantedState(SMB2LeaseState.readHandle())
        lm.register(seededEntry)

        when:
        share.list("testdir")

        then: "the exception propagates"
        thrown(SMBApiException)

        and: "the re-opened handle was closed (openLeasedCacheHandleAndList cleanup)"
        closedFileIds.size() > 0

        cleanup:
        connection.close()
    }

    def "distinct shares on the same connection request different lease keys for their roots"() {
        given: "a connection with two shares and leased create requests captured"
        def requestedLeaseKeys = [] as List<LeaseKey>
        def requestedParentKeys = [] as List<LeaseKey>

        def processor = new DefaultPacketProcessor().wrap({ SMB2Packet req ->
            req = req.getPacket()
            if (req instanceof SMB2NegotiateRequest) {
                return buildNegotiateResponse()
            }
            if (req instanceof SMB2CreateRequest) {
                for (SMB2CreateContext ctx : req.getCreateContexts()) {
                    if (Arrays.equals(ctx.getName(), SMB2LeaseCreateContext.NAME)) {
                        SMBBuffer b = new SMBBuffer(ctx.getData())
                        byte[] keyBytes = b.readRawBytes(16)
                        requestedLeaseKeys << new LeaseKey(keyBytes)
                        b.readUInt32() // leaseState
                        long flags = b.readUInt32() // flags
                        b.skip(8) // duration
                        byte[] parentKeyBytes = b.readRawBytes(16)
                        if ((flags & SMB2LeaseFlags.SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET.getValue()) != 0) {
                            requestedParentKeys << new LeaseKey(parentKeyBytes)
                        }
                    }
                }
                return buildLeasedCreateResponse()
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
        def share1 = session.connectShare("Movies") as DiskShare
        def share2 = session.connectShare("Paylasim") as DiskShare

        when: "the roots of two different shares on the same connection are opened"
        def dir1 = share1.openDirectory("", EnumSet.of(AccessMask.FILE_LIST_DIRECTORY), null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)
        def dir2 = share2.openDirectory("", EnumSet.of(AccessMask.FILE_LIST_DIRECTORY), null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)

        then: "each share requests its own distinct lease key scoped by share"
        requestedLeaseKeys.size() == 2
        requestedLeaseKeys[0] != requestedLeaseKeys[1]

        and: "neither share root sets a parent lease key referencing itself"
        requestedParentKeys.isEmpty()

        cleanup:
        dir1?.closeSilently()
        dir2?.closeSilently()
        connection.close()
    }

    // ---- helpers ----

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

    private static SMB2CreateResponse buildLeasedCreateResponse() {
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
        return resp
    }
}
