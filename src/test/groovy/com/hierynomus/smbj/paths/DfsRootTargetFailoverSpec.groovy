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

import com.hierynomus.msdtyp.FileTime
import com.hierynomus.msdfsc.DFSPath
import com.hierynomus.msdfsc.ReferralCache
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
import org.slf4j.LoggerFactory
import spock.lang.Specification

import java.nio.charset.StandardCharsets

/**
 * Domain-based DFS namespace with one broken root target: the server is listed in the domain's
 * root referral, but its tree connect to the namespace share fails and it does not answer a
 * referral request for a folder link.
 *
 * The stub reproduces the following sequence: the tree connect to the broken target is redirected
 * through that target's own root referral to a healthy target, the create there returns
 * PATH_NOT_COVERED, and the link referral is then sent back to the broken target (every
 * connection has its own referral cache, and the healthy connection's cache does not know about
 * the broken target).
 */
class DfsRootTargetFailoverSpec extends Specification {

    static final String DOM = "example.com"
    static final String BAD = "dc1.example.com"
    static final String GOOD = "dc2.example.com"
    static final String FS = "fs1.example.com"
    static final long REFERRAL_FAILURE = NtStatus.STATUS_NOT_FOUND.value

    SMBClient client
    Map<Long, List<String>> trees = [:]
    long nextTreeId = 100
    List<String> creates = []
    List<String> referrals = []
    List<String> rootTargets = [BAD, GOOD]
    long badLinkReferralStatus = REFERRAL_FAILURE
    int badLinkReferralCap = 25
    boolean badRootReferralWorks = true
    boolean badBroken = true
    int goodLinkCreateFailures = 0
    Closure onGoodLinkReferral = null

    def cleanup() {
        client?.close()
    }

    def "folderExists below a DFS link fails over from a broken root target to the next one"() {
        given:
        def share = connectNamespace()

        when:
        def exists = share.folderExists("sales\\reports\\2026\\q1")

        then:
        exists
        and: "the check reached the link target"
        creates.contains("${FS}\\data:reports\\2026\\q1".toString())
        and: "the broken target was asked for the link exactly once"
        referrals.count { it.startsWith("${BAD}:\\${BAD}\\DFS\\sales".toString()) } == 1
    }

    def "control: with the healthy target first no failover is needed"() {
        given:
        rootTargets = [GOOD, BAD]
        def share = connectNamespace()

        expect:
        share.folderExists("sales\\reports\\2026\\q1")
        referrals.count { it.startsWith("${BAD}:".toString()) } == 0
    }

    def "paths above the link still work through the broken target"() {
        given:
        def share = connectNamespace()

        expect: "\\sales exists although the first target is broken"
        share.folderExists("sales")
    }

    def "when every root target fails the referral status surfaces instead of a NullPointerException"() {
        given:
        rootTargets = [BAD]
        def share = connectNamespace()

        when:
        share.folderExists("sales\\reports\\2026\\q1")

        then:
        def e = thrown(SMBApiException)
        e.statusCode == REFERRAL_FAILURE
    }

    def "a broken target answering PATH_NOT_COVERED still advances to the next target"() {
        given:
        badLinkReferralStatus = NtStatus.STATUS_PATH_NOT_COVERED.value
        def share = connectNamespace()

        when:
        def exists = share.folderExists("sales\\reports\\2026\\q1")

        then:
        exists
        and: "no retry on the same target (the stub's cap of ${badLinkReferralCap} is not reached)"
        referrals.count { it.startsWith("${BAD}:\\${BAD}\\DFS\\sales".toString()) } == 1
    }

    def "a broken target at the end of the list wraps around to the healthy one"() {
        given: "both targets healthy, the first one fails once: the target hint moves to the end of the list"
        rootTargets = [GOOD, BAD]
        badBroken = false
        goodLinkCreateFailures = 1
        def share = connectNamespace()
        assert share.folderExists("sales\\reports\\2026\\q1")

        when: "the target at the end of the list then breaks (BAD_NETWORK_NAME on tree connect)"
        badBroken = true
        badRootReferralWorks = false
        def exists = share.folderExists("sales\\reports\\2026\\q1")

        then: "the access wraps around to the healthy target at the start of the list"
        exists
        creates.count { it == "${FS}\\data:reports\\2026\\q1".toString() } == 2
    }

    def "every root target is tried at most once per access"() {
        given:
        rootTargets = [GOOD, BAD]
        badRootReferralWorks = false
        goodLinkCreateFailures = 100
        def share = connectNamespace()

        when:
        share.folderExists("sales\\reports\\2026\\q1")

        then:
        thrown(SMBApiException)
        goodLinkCreateFailures == 99
    }

    def "switching to the next root target is logged at INFO"() {
        given:
        // logback is only on the test runtime classpath; Groovy resolves the calls dynamically
        def appender = Class.forName("ch.qos.logback.core.read.ListAppender").getDeclaredConstructor().newInstance()
        def logger = LoggerFactory.getLogger(DFSPathResolver)
        appender.start()
        logger.addAppender(appender)
        badRootReferralWorks = false
        def share = connectNamespace()

        when:
        def exists = share.folderExists("sales\\reports\\2026\\q1")

        and: "the target hint stays on the target that worked: no second switch"
        def again = share.folderExists("sales\\reports\\2026\\q1")

        then:
        exists
        again
        def switches = appender.list.findAll { it.level.toString() == "INFO" && it.formattedMessage.contains("trying") }
        switches.size() == 1
        switches[0].formattedMessage.contains("\\\\${BAD}\\DFS".toString())
        switches[0].formattedMessage.contains("STATUS_BAD_NETWORK_NAME")
        switches[0].formattedMessage.contains("\\\\${GOOD}\\DFS".toString())

        cleanup:
        logger.detachAppender(appender)
    }

    def "a slow access does not move the target hint back after another access has moved it"() {
        given: "both root targets healthy, the hint on the first one"
        rootTargets = [GOOD, BAD]
        badBroken = false
        def share = connectNamespace()

        and: "while this access waits for the first target, another access moves the hint to the second one"
        def moved = []
        onGoodLinkReferral = {
            onGoodLinkReferral = null
            def entries = rootEntries()
            assert entries.size() == 1
            moved << entries[0].compareAndSetTargetHintIndex(0, 1)
        }

        when:
        def exists = share.folderExists("sales\\reports\\2026\\q1")

        then: "the access succeeds on the first target, but keeps the newer hint"
        exists
        moved == [true]
        referrals.count { it.startsWith("${GOOD}:\\${GOOD}\\DFS\\sales".toString()) } == 1
        rootEntries()*.targetHintIndex == [1]
    }

    def "control: without a concurrent change the hint stays on the target that worked"() {
        given:
        rootTargets = [GOOD, BAD]
        badBroken = false
        def share = connectNamespace()

        expect:
        share.folderExists("sales\\reports\\2026\\q1")
        rootEntries()*.targetHintIndex == [0]
    }

    private List<ReferralCache.ReferralCacheEntry> rootEntries() {
        def path = new DFSPath("\\\\${DOM}\\DFS\\sales\\reports\\2026\\q1".toString())
        return client.@connectionTable.values()
            .collect { it.@pathResolver }
            .findAll { it instanceof DFSPathResolver }
            .collect { it.@referralCache.lookup(path) }
            .findAll { it != null && it.isRoot() }
    }

    private DiskShare connectNamespace() {
        def processor = new DefaultPacketProcessor().wrap({ SMB2Packet req -> respond(req.getPacket()) })
        def config = SmbConfig.builder()
            .withDfsEnabled(true)
            .withTransportLayerFactory(new StubTransportLayerFactory(processor))
            .withAuthenticators(new StubAuthenticator.Factory())
            .build()
        client = new SMBClient(config)
        def session = client.connect(DOM).authenticate(new AuthenticationContext("user", "pass".toCharArray(), "domain"))
        return session.connectShare("DFS") as DiskShare
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
        if (host == BAD && share == "DFS" && badBroken) {
            resp.header.statusCode = NtStatus.STATUS_BAD_NETWORK_NAME.value
            return resp
        }
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
        if (host == DOM && p.startsWith("\\${DOM}\\dfs".toString())) {
            return referralResponse(DFSReferral.ServerType.ROOT, "\\${DOM}\\DFS", rootTargets.collect { "\\${it}\\DFS".toString() })
        }
        if (host == BAD && p == "\\${BAD}\\dfs".toString() && badRootReferralWorks) {
            return referralResponse(DFSReferral.ServerType.ROOT, "\\${BAD}\\DFS", ["\\${GOOD}\\DFS".toString()])
        }
        if (host == BAD && !badBroken && p.startsWith("\\${BAD}\\dfs\\sales\\reports".toString())) {
            return referralResponse(DFSReferral.ServerType.LINK, "\\${BAD}\\DFS\\sales\\reports", ["\\${FS}\\data\\reports".toString()])
        }
        if (host == BAD) {
            def badLinkReferrals = referrals.count { it.startsWith("${BAD}:\\${BAD}\\DFS\\sales".toString()) }
            return failedReferral(badLinkReferrals < badLinkReferralCap ? badLinkReferralStatus : REFERRAL_FAILURE)
        }
        if (host == GOOD && p.startsWith("\\${GOOD}\\dfs\\sales\\reports".toString())) {
            onGoodLinkReferral?.call()
            return referralResponse(DFSReferral.ServerType.LINK, "\\${GOOD}\\DFS\\sales\\reports", ["\\${FS}\\data\\reports".toString()])
        }
        return failedReferral(REFERRAL_FAILURE)
    }

    private SMB2Packet create(String host, String share, String path) {
        creates << "${host}\\${share}:${path}".toString()
        def resp = new SMB2CreateResponse()
        def belowLink = path.toLowerCase() == "sales\\reports" || path.toLowerCase().startsWith("sales\\reports\\")
        if (host == BAD && share == "DFS" && badBroken) {
            // a removed share also affects the already connected tree
            resp.header.statusCode = NtStatus.STATUS_NETWORK_NAME_DELETED.value
            return resp
        }
        if (host == GOOD && share == "DFS" && belowLink && goodLinkCreateFailures > 0) {
            goodLinkCreateFailures--
            resp.header.statusCode = NtStatus.STATUS_INSUFFICIENT_RESOURCES.value
            return resp
        }
        if (share == "DFS" && belowLink) {
            resp.header.statusCode = NtStatus.STATUS_PATH_NOT_COVERED.value
            return resp
        }
        resp.header.statusCode = NtStatus.STATUS_SUCCESS.value
        resp.fileAttributes = EnumSet.of(FileAttributes.FILE_ATTRIBUTE_DIRECTORY)
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
        int stringsStart = 8 + entrySize * targets.size()
        int stringOffset = stringsStart
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

    private static SMB2Packet failedReferral(long status) {
        def resp = new SMB2IoctlResponse()
        resp.header.statusCode = status
        return resp
    }
}
