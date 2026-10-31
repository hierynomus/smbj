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
package com.hierynomus.smbj.paths

import com.hierynomus.msdtyp.AccessMask
import com.hierynomus.msfscc.FileAttributes
import com.hierynomus.mserref.NtStatus
import com.hierynomus.mssmb2.SMB2CreateDisposition
import com.hierynomus.mssmb2.SMB2Error
import com.hierynomus.mssmb2.SMB2FileId
import com.hierynomus.mssmb2.SMB2Packet
import com.hierynomus.mssmb2.SMB2ShareAccess
import com.hierynomus.mssmb2.SMBApiException
import com.hierynomus.mssmb2.messages.SMB2Close
import com.hierynomus.mssmb2.messages.SMB2CreateRequest
import com.hierynomus.mssmb2.messages.SMB2CreateResponse
import com.hierynomus.mssmb2.messages.SMB2QueryDirectoryRequest
import com.hierynomus.mssmb2.messages.SMB2TreeConnectRequest
import com.hierynomus.mssmb2.messages.SMB2TreeConnectResponse
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.common.SmbPath
import com.hierynomus.smbj.session.Session
import com.hierynomus.smbj.share.DiskShare
import com.hierynomus.smbj.testing.PacketProcessor.DefaultPacketProcessor
import com.hierynomus.smbj.testing.StubAuthenticator
import com.hierynomus.smbj.testing.StubTransportLayerFactory
import com.hierynomus.smbj.transport.TransportLayerFactory
import spock.lang.Specification
import spock.lang.Unroll

import java.util.concurrent.TimeUnit

class SmbConfigPathResolverSpec extends Specification {

    private SMBClient client
    private Session session
    private List<SMB2Packet> requests = []
    private int transportCount

    def cleanup() {
        client?.close()
    }

    @Unroll
    def "LOCAL does not follow #operation symlinks to #target"() {
        given:
        def share = connectShare(PathResolver.LOCAL, symlinkResponse(absolute, target))

        when:
        open(share, operation)

        then:
        def exception = thrown(SMBApiException)
        exception.statusCode == NtStatus.STATUS_STOPPED_ON_SYMLINK.value
        requests.count { it instanceof SMB2CreateRequest } == 1
        requests.count { it instanceof SMB2TreeConnectRequest } == 1
        requests.count { it instanceof SMB2QueryDirectoryRequest } == 0
        transportCount == 1

        where:
        operation   | absolute | target
        "file"      | false    | "target"
        "directory" | false    | "target"
        "list"      | false    | "target"
        "file"      | true     | "\\??\\UNC\\127.0.0.1\\other-share\\target"
        "directory" | true     | "\\??\\UNC\\127.0.0.1\\other-share\\target"
        "list"      | true     | "\\??\\UNC\\127.0.0.1\\other-share\\target"
        "file"      | true     | "\\??\\UNC\\127.0.0.2\\other-share\\target"
        "directory" | true     | "\\??\\UNC\\127.0.0.2\\other-share\\target"
        "list"      | true     | "\\??\\UNC\\127.0.0.2\\other-share\\target"
    }

    def "default resolver sends a second CREATE to the symlink target"() {
        given:
        def share = connectShare(null, symlinkResponse(false, "target"))

        when:
        def file = open(share, "file")

        then:
        requests.findAll { it instanceof SMB2CreateRequest }.collect { it.path.path } ==
            ["link\\child", "target\\child"]
        requests.count { it instanceof SMB2TreeConnectRequest } == 1
        transportCount == 1

        cleanup:
        file?.close()
    }

    def "configured resolver handles TREE_CONNECT and CREATE on the cached share"() {
        given:
        def resolvedResponses = []
        def resolvedPaths = []
        def resolver = Stub(PathResolver) {
            statusHandler() >> PathResolver.LOCAL.statusHandler()
            resolve(_, _, _, _) >> { currentSession, response, path, action ->
                resolvedResponses << response
                action.apply(path)
            }
            resolve(_, _, _) >> { currentSession, path, action ->
                resolvedPaths << path
                action.apply(path)
            }
        }
        def share = connectShare(resolver, successfulCreateResponse())

        when:
        def file = open(share, "file")

        then:
        resolvedResponses.size() == 2
        resolvedResponses[0] instanceof SMB2TreeConnectResponse
        resolvedResponses[1] instanceof SMB2CreateResponse
        resolvedPaths == [new SmbPath("127.0.0.1", "share", "link\\child")]
        session.connectShare("share").is(share)
        requests.count { it instanceof SMB2TreeConnectRequest } == 1

        cleanup:
        file?.close()
    }

    private DiskShare connectShare(PathResolver resolver, SMB2CreateResponse firstCreateResponse) {
        def processor = new DefaultPacketProcessor().wrap({ SMB2Packet request ->
            request = request.packet
            requests << request
            if (request instanceof SMB2CreateRequest) {
                return requests.count { it instanceof SMB2CreateRequest } == 1 ?
                    firstCreateResponse : successfulCreateResponse()
            }
            if (request instanceof SMB2Close) {
                def response = new SMB2Close()
                response.header.statusCode = NtStatus.STATUS_SUCCESS.value
                return response
            }
            null
        })
        def transportFactory = new StubTransportLayerFactory(processor)
        def countingFactory = { handlers, config ->
            transportCount++
            transportFactory.createTransportLayer(handlers, config)
        } as TransportLayerFactory
        def builder = SmbConfig.builder()
            .withDfsEnabled(false)
            .withTimeout(1, TimeUnit.SECONDS)
            .withTransportLayerFactory(countingFactory)
            .withAuthenticators(new StubAuthenticator.Factory())
        if (resolver != null) {
            builder.withPathResolver(resolver)
        }
        client = new SMBClient(builder.build())
        def connection = client.connect("127.0.0.1")
        session = connection.authenticate(new AuthenticationContext("user", "pass".toCharArray(), "domain"))
        return session.connectShare("share") as DiskShare
    }

    private static Object open(DiskShare share, String operation) {
        if (operation == "file") {
            return share.openFile("link\\child", EnumSet.of(AccessMask.GENERIC_READ), null,
                SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)
        }
        if (operation == "directory") {
            return share.openDirectory("link\\child", EnumSet.of(AccessMask.GENERIC_READ), null,
                SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)
        }
        return share.list("link\\child")
    }

    private static SMB2CreateResponse symlinkResponse(boolean absolute, String target) {
        def symlink = new SMB2Error.SymbolicLinkError()
        symlink['absolute'] = absolute
        symlink['unparsedPathLength'] = "\\child".length() * 2
        symlink['substituteName'] = target
        symlink['printName'] = target
        def error = new SMB2Error()
        error.errorData.add(symlink)
        def response = new SMB2CreateResponse()
        response.header.statusCode = NtStatus.STATUS_STOPPED_ON_SYMLINK.value
        response.error = error
        return response
    }

    private static SMB2CreateResponse successfulCreateResponse() {
        def response = new SMB2CreateResponse()
        response.header.statusCode = NtStatus.STATUS_SUCCESS.value
        response.fileId = new SMB2FileId(new byte[8], new byte[8])
        response.fileAttributes = EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL)
        return response
    }
}
