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
import com.hierynomus.mssmb2.SMB2FileId
import com.hierynomus.mssmb2.SMB2GlobalCapability
import com.hierynomus.mssmb2.SMB2LeaseState
import com.hierynomus.mssmb2.SMBApiException
import com.hierynomus.mssmb2.messages.SMB2Close
import com.hierynomus.mssmb2.messages.SMB2CreateRequest
import com.hierynomus.mssmb2.messages.SMB2CreateResponse
import com.hierynomus.mssmb2.messages.SMB2NegotiateRequest
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse
import com.hierynomus.mssmb2.messages.SMB2SetInfoRequest
import com.hierynomus.mssmb2.messages.SMB2SetInfoResponse
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.common.SmbPath
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.connection.LeaseEntry
import com.hierynomus.smbj.testing.PacketProcessor.DefaultPacketProcessor
import com.hierynomus.smbj.testing.StubAuthenticator
import com.hierynomus.smbj.testing.StubTransportLayerFactory
import spock.lang.Specification

class DiskEntrySpec extends Specification {
    private Connection connection
    private DiskShare share
    private long renameStatus = NtStatus.STATUS_SUCCESS.value

    def setup() {
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
            if (request instanceof SMB2SetInfoRequest) {
                def response = new SMB2SetInfoResponse()
                response.header.statusCode = renameStatus
                return response
            }
            if (request instanceof SMB2CreateRequest) {
                def response = new SMB2CreateResponse()
                response.header.statusCode = NtStatus.STATUS_OBJECT_NAME_NOT_FOUND.value
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
        share = session.connectShare("share") as DiskShare
    }

    def cleanup() {
        connection?.close()
    }

    def "rename invalidates destination caches within its share"() {
        given:
        def source = cacheDirectory("share", "source")
        def shareRelativeTarget = cacheDirectory("share", "relative")
        def handleRelativeTarget = cacheDirectory("share", "target\\relative")
        def unrelated = cacheDirectory("share", "unrelated")
        def otherShare = cacheDirectory("other-share", "target\\relative")
        def entry = new File(new SMB2FileId(), share, new SmbPath("127.0.0.1", "share", "source\\file.txt"))

        when:
        entry.rename("relative\\renamed.txt", false)

        then:
        source.cache.size() == 0
        shareRelativeTarget.cache.size() == 0
        handleRelativeTarget.cache.size() == 1
        unrelated.cache.size() == 1
        otherShare.cache.size() == 1
    }

    def "a rejected rename preserves directory caches"() {
        given:
        renameStatus = NtStatus.STATUS_ACCESS_DENIED.value
        def source = cacheDirectory("share", "source")
        def destination = cacheDirectory("share", "relative")
        def entry = new File(new SMB2FileId(), share, new SmbPath("127.0.0.1", "share", "source\\file.txt"))

        when:
        entry.rename("relative\\renamed.txt", false)

        then:
        thrown(SMBApiException)
        source.cache.size() == 1
        destination.cache.size() == 1
        entry.path == "source\\file.txt"
    }

    def "renaming a directory evicts both subtrees and prevents listing the old path from cache"() {
        given:
        def parent = cacheDirectory("share", "")
        def source = cacheDirectory("share", "a")
        def child = cacheDirectory("share", "a\\child")
        def destination = cacheDirectory("share", "b")
        def destinationChild = cacheDirectory("share", "b\\child")
        def sibling = cacheDirectory("share", "abc")
        def otherShare = cacheDirectory("other-share", "a")
        def cachedHandle = Mock(Directory)
        source.cacheDirectory = cachedHandle
        def entry = new Directory(new SMB2FileId(), share, new SmbPath("127.0.0.1", "share", "a"))
        assert share.list("a").empty

        when:
        entry.rename("b", true)

        then:
        1 * cachedHandle.closeSilently()
        [parent, source, child, destination, destinationChild].every { it.cache.size() == 0 }
        ["a", "a\\child", "b", "b\\child"].every { connection.leaseManager.getByPath("share", it) == null }
        sibling.cache.size() == 1
        otherShare.cache.size() == 1
        entry.path == "b"
        entry.uncPath == "\\\\127.0.0.1\\share\\b"

        when:
        share.list("a")

        then:
        def exception = thrown(SMBApiException)
        exception.status == NtStatus.STATUS_OBJECT_NAME_NOT_FOUND
    }

    def "successive renames and deletion invalidate the current parent of the same handle"() {
        given:
        def a = cacheDirectory("share", "a")
        def b = cacheDirectory("share", "b")
        def c = cacheDirectory("share", "c")
        def entry = new File(new SMB2FileId(), share, new SmbPath("127.0.0.1", "share", "a\\f"))

        when:
        entry.rename("b/f")

        then:
        a.cache.size() == 0
        b.cache.size() == 0
        c.cache.size() == 1
        entry.path == "b\\f"

        when:
        populateCache(a)
        populateCache(b)
        entry.rename("c/f")

        then:
        a.cache.size() == 1
        b.cache.size() == 0
        c.cache.size() == 0
        entry.path == "c\\f"

        when:
        populateCache(b)
        populateCache(c)
        entry.deleteOnClose()

        then:
        a.cache.size() == 1
        b.cache.size() == 1
        c.cache.size() == 0
    }


    def "direct directory deletion closes its cache handle and evicts its subtree before the app handle closes"() {
        given:
        def parent = cacheDirectory("share", "parent")
        def directory = cacheDirectory("share", "parent\\dir")
        def child = cacheDirectory("share", "parent\\dir\\child")
        def cachedHandle = Mock(Directory)
        directory.cacheDirectory = cachedHandle
        def entry = new Directory(new SMB2FileId(), share, new SmbPath("127.0.0.1", "share", "parent\\dir"))

        when:
        entry.deleteOnClose()

        then:
        1 * cachedHandle.closeSilently()
        directory.cacheDirectory == null
        [parent, directory, child].every { it.cache.size() == 0 }
        connection.leaseManager.getByPath("share", "parent\\dir") == null
        connection.leaseManager.getByPath("share", "parent\\dir\\child") == null

        when:
        entry.close()

        then:
        0 * cachedHandle.closeSilently()
    }

    def "a rejected directory deletion preserves its subtree and cache handle"() {
        given:
        renameStatus = NtStatus.STATUS_ACCESS_DENIED.value
        def directory = cacheDirectory("share", "parent\\dir")
        def child = cacheDirectory("share", "parent\\dir\\child")
        def cachedHandle = Mock(Directory)
        directory.cacheDirectory = cachedHandle
        def entry = new Directory(new SMB2FileId(), share, new SmbPath("127.0.0.1", "share", "parent\\dir"))

        when:
        entry.deleteOnClose()

        then:
        thrown(SMBApiException)
        0 * cachedHandle.closeSilently()
        directory.cacheDirectory.is(cachedHandle)
        directory.cache.size() == 1
        child.cache.size() == 1
    }

    private LeaseEntry cacheDirectory(String shareName, String path) {
        def manager = connection.leaseManager
        def entry = new LeaseEntry(manager.leaseKeyForPath(shareName, path), null,
            SMB2LeaseState.readHandle(), shareName, path)
        entry.setOwner(share.session, share.treeConnect.treeId, SMB2Dialect.SMB_3_0)
        manager.register(entry)
        entry.granted = true
        entry.grantedState = SMB2LeaseState.readHandle()
        populateCache(entry)
        entry
    }

    private void populateCache(LeaseEntry entry) {
        entry.cache.populate(entry.shareName, entry.path, FileIdBothDirectoryInformation, null, [])
    }
}
