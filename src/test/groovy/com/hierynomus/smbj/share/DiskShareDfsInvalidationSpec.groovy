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
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation
import com.hierynomus.mssmb2.SMB2CreateAction
import com.hierynomus.mssmb2.SMB2CreateDisposition
import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.mssmb2.SMB2FileId
import com.hierynomus.mssmb2.SMB2GlobalCapability
import com.hierynomus.mssmb2.SMB2LeaseState
import com.hierynomus.mssmb2.SMB2OplockLevel
import com.hierynomus.mssmb2.SMB2Packet
import com.hierynomus.mssmb2.SMB2ShareAccess
import com.hierynomus.mssmb2.messages.SMB2Close
import com.hierynomus.mssmb2.messages.SMB2CreateRequest
import com.hierynomus.mssmb2.messages.SMB2CreateResponse
import com.hierynomus.mssmb2.messages.SMB2NegotiateRequest
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.common.SmbPath
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.connection.LeaseEntry
import com.hierynomus.smbj.connection.LeaseManager
import com.hierynomus.smbj.paths.PathResolver
import com.hierynomus.smbj.testing.PacketProcessor.DefaultPacketProcessor
import com.hierynomus.smbj.testing.StubAuthenticator
import com.hierynomus.smbj.testing.StubTransportLayerFactory
import spock.lang.Specification
import spock.lang.Unroll

class DiskShareDfsInvalidationSpec extends Specification {
    private Connection connection

    def cleanup() {
        connection?.close()
    }

    @Unroll
    def "redirected #kind using #disposition with #action invalidates both parents without forwarding its lease (reactive: #reactive)"() {
        given:
        def requestedPaths = []
        def requestedDispositions = []
        def requestedLeases = []
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
            if (request instanceof SMB2CreateRequest) {
                requestedPaths << request.path
                requestedDispositions << request.createDisposition
                requestedLeases << !request.createContexts.empty
                assert request.requestedOplockLevel == (requestedLeases.last()
                    ? SMB2OplockLevel.SMB2_OPLOCK_LEVEL_LEASE : SMB2OplockLevel.SMB2_OPLOCK_LEVEL_NONE)
                def response = new SMB2CreateResponse()
                if (reactive && request.path.shareName == "source") {
                    response.header.statusCode = NtStatus.STATUS_PATH_NOT_COVERED.value
                    return response
                }
                response.header.statusCode = NtStatus.STATUS_SUCCESS.value
                response.fileId = new SMB2FileId(new byte[8], new byte[8])
                response.fileAttributes = EnumSet.of(directory
                    ? FileAttributes.FILE_ATTRIBUTE_DIRECTORY : FileAttributes.FILE_ATTRIBUTE_NORMAL)
                response.@createAction = action
                return response
            }
            if (request instanceof SMB2Close) {
                def response = new SMB2Close()
                response.header.statusCode = NtStatus.STATUS_SUCCESS.value
                return response
            }
            null
        })
        def config = SmbConfig.builder()
            .withDirectoryLeasingEnabled(true)
            .withDfsEnabled(false)
            .withTransportLayerFactory(new StubTransportLayerFactory(processor))
            .withAuthenticators(new StubAuthenticator.Factory())
            .build()
        connection = new SMBClient(config).connect("127.0.0.1")
        def session = connection.authenticate(new AuthenticationContext("user", "pass".toCharArray(), "domain"))
        def original = session.connectShare("source") as DiskShare
        def resolvedShare = session.connectShare("target") as DiskShare
        def resolvedPath = new SmbPath("127.0.0.1", "target", "actual\\entry")
        def resolver = Stub(PathResolver) {
            statusHandler() >> ({ status -> status == NtStatus.STATUS_SUCCESS.value
                || status == NtStatus.STATUS_PATH_NOT_COVERED.value } as StatusHandler)
            resolve(_, _ as SmbPath, _) >> { ignored, path, resolveAction ->
                resolveAction.apply(reactive ? path : resolvedPath)
            }
            resolve(_, _ as SMB2Packet, _, _) >> { ignored, response, path, resolveAction ->
                path == resolvedPath ? null : resolveAction.apply(resolvedPath)
            }
        }
        def redirected = new DiskShare(original.smbPath, original.treeConnect, resolver)
        def originalParent = cachedParent(connection.leaseManager, "source", "alias")
        def resolvedParent = cachedParent(connection.leaseManager, "target", "actual")
        def unrelatedParent = cachedParent(connection.leaseManager, "source", "unrelated")

        when:
        def opened = directory
            ? redirected.openDirectory("alias\\entry", EnumSet.of(AccessMask.FILE_LIST_DIRECTORY), null,
                SMB2ShareAccess.ALL, disposition, null)
            : redirected.openFile("alias\\entry", EnumSet.of(AccessMask.GENERIC_WRITE), null,
                SMB2ShareAccess.ALL, disposition, null)

        then:
        requestedPaths == (reactive ? [new SmbPath("127.0.0.1", "source", "alias\\entry"), resolvedPath] : [resolvedPath])
        requestedDispositions == Collections.nCopies(reactive ? 2 : 1, disposition)
        requestedLeases == (reactive ? [directory, false] : [false])
        opened.diskShare.is(resolvedShare)
        opened.path == "actual\\entry"
        connection.leaseManager.getByPath("source", "alias\\entry") == null
        originalParent.cacheGeneration == (action == SMB2CreateAction.FILE_OPENED ? 0 : 1)
        (originalParent.cache.serve("source", "alias", FileIdBothDirectoryInformation, null) == null) ==
            (action != SMB2CreateAction.FILE_OPENED)
        resolvedParent.cacheGeneration == (action == SMB2CreateAction.FILE_OPENED ? 0 : 1)
        (resolvedParent.cache.serve("target", "actual", FileIdBothDirectoryInformation, null) == null) ==
            (action != SMB2CreateAction.FILE_OPENED)
        unrelatedParent.cacheGeneration == 0
        unrelatedParent.cache.serve("source", "unrelated", FileIdBothDirectoryInformation, null) != null

        cleanup:
        opened?.close()

        where:
        directory | disposition                           | action                           | reactive
        false     | SMB2CreateDisposition.FILE_OPEN_IF     | SMB2CreateAction.FILE_CREATED     | false
        false     | SMB2CreateDisposition.FILE_SUPERSEDE   | SMB2CreateAction.FILE_SUPERSEDED  | false
        false     | SMB2CreateDisposition.FILE_OVERWRITE   | SMB2CreateAction.FILE_OVERWRITTEN | false
        false     | SMB2CreateDisposition.FILE_OPEN_IF     | SMB2CreateAction.FILE_OPENED      | false
        true      | SMB2CreateDisposition.FILE_OPEN_IF     | SMB2CreateAction.FILE_CREATED     | false
        true      | SMB2CreateDisposition.FILE_OPEN_IF     | SMB2CreateAction.FILE_OPENED      | false
        true      | SMB2CreateDisposition.FILE_OPEN_IF     | SMB2CreateAction.FILE_CREATED     | true
        kind = directory ? "directory open with leasing" : "file open"
    }

    private static LeaseEntry cachedParent(LeaseManager manager, String share, String path) {
        def entry = new LeaseEntry(manager.leaseKeyForPath(share, path), null,
            SMB2LeaseState.readHandle(), share, path)
        entry.granted = true
        entry.grantedState = SMB2LeaseState.readHandle()
        entry.cache.populate(share, path, FileIdBothDirectoryInformation, null, [])
        manager.register(entry)
        entry
    }
}
