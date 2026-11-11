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
import com.hierynomus.msdtyp.FileTime
import com.hierynomus.msdfsc.messages.DFSReferral
import com.hierynomus.msfscc.FileAttributes
import com.hierynomus.mserref.NtStatus
import com.hierynomus.mssmb2.*
import com.hierynomus.mssmb2.messages.*
import com.hierynomus.smb.SMBBuffer
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.share.DiskShare
import com.hierynomus.smbj.testing.PacketProcessor.DefaultPacketProcessor
import com.hierynomus.smbj.testing.StubAuthenticator
import com.hierynomus.smbj.testing.StubTransportLayerFactory
import spock.lang.Specification

import java.nio.charset.StandardCharsets

/**
 * A DFS namespace root target that answers a create below a folder link with
 * STATUS_ACCESS_DENIED instead of STATUS_PATH_NOT_COVERED.
 *
 * Domain-based namespace \\example.com\namespace with the root target
 * \\dc1.example.com\namespace and the folder link "projects" pointing to
 * \\fs1.example.com\data\projects. The root target denies creates below the link;
 * "private" is a plain folder of the namespace that is really denied.
 */
class DfsAccessDeniedSpec extends Specification {

    static final String DOMAIN = "example.com"
    static final String ROOT_HOST = "dc1.example.com"
    static final String ROOT_SHARE = "namespace"
    static final String LINK_HOST = "fs1.example.com"
    static final String LINK_SHARE = "data"

    SMBClient client
    Map<Long, List<String>> trees = [:]
    long nextTreeId = 100
    List<String> creates = []
    List<String> referrals = []

    def cleanup() {
        client?.close()
    }

    def "a create below a folder link that the root target denies follows the link"() {
        given:
        def share = connectNamespace()

        when:
        def file = share.openFile("projects\\2026\\report.txt", EnumSet.of(AccessMask.GENERIC_WRITE), null,
            SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OVERWRITE_IF, null)
        file.close()

        then:
        creates.contains("${LINK_HOST}\\${LINK_SHARE}:projects\\2026\\report.txt".toString())
        and: "the namespace root target was asked only once"
        creates.count { it == "${ROOT_HOST}\\${ROOT_SHARE}:projects\\2026\\report.txt".toString() } == 1
    }

    def "a real denial outside any folder link is still thrown"() {
        given:
        def share = connectNamespace()

        when:
        share.openFile("private\\secret.txt", EnumSet.of(AccessMask.GENERIC_WRITE), null,
            SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OVERWRITE_IF, null)

        then:
        def e = thrown(SMBApiException)
        e.statusCode == NtStatus.STATUS_ACCESS_DENIED.value
        creates.count { it == "${ROOT_HOST}\\${ROOT_SHARE}:private\\secret.txt".toString() } == 1
        creates.findAll { it.startsWith("${LINK_HOST}\\".toString()) }.isEmpty()
    }

    def "a denial on the link target itself is thrown without another retry"() {
        given:
        def share = connectNamespace()

        when:
        share.openFile("projects\\readonly\\report.txt", EnumSet.of(AccessMask.GENERIC_WRITE), null,
            SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OVERWRITE_IF, null)

        then:
        def e = thrown(SMBApiException)
        e.statusCode == NtStatus.STATUS_ACCESS_DENIED.value
        creates.count { it == "${LINK_HOST}\\${LINK_SHARE}:projects\\readonly\\report.txt".toString() } == 1
        creates.count { it == "${ROOT_HOST}\\${ROOT_SHARE}:projects\\readonly\\report.txt".toString() } == 1
    }

    private DiskShare connectNamespace() {
        def processor = new DefaultPacketProcessor().wrap({ SMB2Packet req -> respond(req.getPacket()) })
        def config = SmbConfig.builder()
            .withDfsEnabled(true)
            .withTransportLayerFactory(new StubTransportLayerFactory(processor))
            .withAuthenticators(new StubAuthenticator.Factory())
            .build()
        client = new SMBClient(config)
        def session = client.connect(DOMAIN).authenticate(new AuthenticationContext("user", "pass".toCharArray(), "EXAMPLE"))
        return session.connectShare(ROOT_SHARE) as DiskShare
    }

    private SMB2Packet respond(SMB2Packet req) {
        if (req instanceof SMB2NegotiateRequest) {
            def resp = new SMB2NegotiateResponse()
            resp.header.statusCode = NtStatus.STATUS_SUCCESS.value
            resp.dialect = SMB2Dialect.SMB_2_1
            resp.systemTime = FileTime.now()
            resp.serverGuid = UUID.randomUUID()
            resp.capabilities = EnumSet.of(SMB2GlobalCapability.SMB2_GLOBAL_CAP_DFS)
            return resp
        }
        if (req instanceof SMB2TreeConnectRequest) {
            return treeConnect(req.smbPath.hostname, req.smbPath.shareName)
        }
        if (req instanceof SMB2IoctlRequest) {
            return referral(trees[req.header.treeId][0], requestedReferralPath(req))
        }
        if (req instanceof SMB2CreateRequest) {
            def tree = trees[req.header.treeId]
            return create(tree[0], tree[1], req.@path.path ?: "")
        }
        if (req instanceof SMB2Close) {
            def resp = new SMB2Close()
            resp.header.statusCode = NtStatus.STATUS_SUCCESS.value
            return resp
        }
        return null
    }

    private SMB2Packet treeConnect(String host, String share) {
        def resp = new SMB2TreeConnectResponse()
        long id = nextTreeId++
        trees[id] = [host, share]
        resp.header.statusCode = NtStatus.STATUS_SUCCESS.value
        resp.header.treeId = id
        resp.capabilities = EnumSet.of(SMB2ShareCapabilities.SMB2_SHARE_CAP_DFS)
        resp.shareFlags = EnumSet.noneOf(SMB2ShareFlags.class)
        resp.shareType = (byte) (share == "IPC\$" ? 0x02 : 0x01)
        return resp
    }

    private SMB2Packet referral(String host, String path) {
        referrals << "${host}:${path}".toString()
        def p = path.toLowerCase()
        def namespace = "\\${DOMAIN}\\${ROOT_SHARE}".toString()
        def root = "\\${ROOT_HOST}\\${ROOT_SHARE}".toString()
        if (host == DOMAIN && p.startsWith(namespace)) {
            return referralResponse(DFSReferral.ServerType.ROOT, namespace, [root])
        }
        if (host == ROOT_HOST && p.startsWith("${root}\\projects".toString())) {
            return referralResponse(DFSReferral.ServerType.LINK, "${root}\\projects", ["\\${LINK_HOST}\\${LINK_SHARE}\\projects".toString()])
        }
        if (host == ROOT_HOST && p.startsWith(root)) {
            return referralResponse(DFSReferral.ServerType.ROOT, root, [root])
        }
        def resp = new SMB2IoctlResponse()
        resp.header.statusCode = NtStatus.STATUS_NOT_FOUND.value
        return resp
    }

    private SMB2Packet create(String host, String share, String path) {
        creates << "${host}\\${share}:${path}".toString()
        def resp = new SMB2CreateResponse()
        def p = path.toLowerCase()
        def denied = (host == ROOT_HOST && share == ROOT_SHARE && (p.startsWith("projects\\") || p.startsWith("private\\"))) ||
            (host == LINK_HOST && p.startsWith("projects\\readonly\\"))
        if (denied) {
            resp.header.statusCode = NtStatus.STATUS_ACCESS_DENIED.value
            return resp
        }
        resp.header.statusCode = NtStatus.STATUS_SUCCESS.value
        resp.fileAttributes = path.isEmpty() ? EnumSet.of(FileAttributes.FILE_ATTRIBUTE_DIRECTORY) : EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL)
        resp.fileId = new SMB2FileId(new byte[8], new byte[8])
        return resp
    }

    private static String requestedReferralPath(SMB2IoctlRequest req) {
        def out = new ByteArrayOutputStream()
        req.@inputData.writeChunk(out)
        def bytes = out.toByteArray()
        // MaxReferralLevel (2 bytes), followed by RequestFileName as null-terminated UTF-16LE
        def name = new String(bytes, 2, bytes.length - 2, StandardCharsets.UTF_16LE)
        return name.indexOf('\u0000') >= 0 ? name.substring(0, name.indexOf('\u0000')) : name
    }

    /**
     * Version 4 referral response, encoded by hand in the layout of the sample data in
     * SMB2GetDFSReferralResponseTest: header (8 bytes), one 34 byte entry per target, then the
     * UTF-16 strings; string offsets are relative to the start of their entry.
     */
    private static SMB2Packet referralResponse(DFSReferral.ServerType type, String dfsPath, List<String> targets) {
        def buf = new SMBBuffer()
        buf.putUInt16(0) // PathConsumed
        buf.putUInt16(targets.size()) // NumberOfReferrals
        buf.putUInt32(0x2) // ReferralHeaderFlags: StorageServers
        int entrySize = 34
        int stringOffset = 8 + entrySize * targets.size()
        def strings = []
        targets.eachWithIndex { String target, int i ->
            int entryStart = 8 + entrySize * i
            buf.putUInt16(4) // VersionNumber
            buf.putUInt16(entrySize) // Size
            buf.putUInt16(type == DFSReferral.ServerType.ROOT ? 1 : 0) // ServerType
            buf.putUInt16(0) // ReferralEntryFlags
            buf.putUInt32(600) // TimeToLive
            [dfsPath, dfsPath, target].each { String s ->
                buf.putUInt16(stringOffset - entryStart)
                stringOffset += (s.length() + 1) * 2
                strings << s
            }
            buf.putRawBytes(new byte[16]) // ServiceSiteGuid
        }
        strings.each { String s -> buf.putRawBytes((s + "\u0000").getBytes(StandardCharsets.UTF_16LE)) }
        def resp = new SMB2IoctlResponse()
        resp.header.statusCode = NtStatus.STATUS_SUCCESS.value
        resp.@outputBuffer = buf.getCompactData()
        return resp
    }
}
