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
package com.hierynomus.smbj.paths;

import com.hierynomus.msdfsc.DFSException;
import com.hierynomus.msdfsc.DFSPath;
import com.hierynomus.msdfsc.DomainCache;
import com.hierynomus.msdfsc.ReferralCache;
import com.hierynomus.msdfsc.messages.SMB2GetDFSReferralRequest;
import com.hierynomus.msdfsc.messages.SMB2GetDFSReferralResponse;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.mssmb2.messages.SMB2IoctlResponse;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.io.BufferByteChunkProvider;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.Share;
import com.hierynomus.smbj.share.StatusHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public class DFSPathResolver implements PathResolver {
    private static final Logger logger = LoggerFactory.getLogger(DFSPathResolver.class);
    private static final long FSCTL_DFS_GET_REFERRALS = 0x00060194L;
    private static final long FSCTL_DFS_GET_REFERRALS_EX = 0x000601B0L;
    private final StatusHandler statusHandler;

    private final PathResolver wrapped;

    private enum DfsRequestType {
        DOMAIN,
        DC,
        SYSVOL,
        ROOT,
        LINK
    }

    private ReferralCache referralCache = new ReferralCache();

    private DomainCache domainCache = new DomainCache();
    private long transactTimeout;

    public DFSPathResolver(final PathResolver wrapped, long transactTimeout) {
        this.wrapped = wrapped;
        this.transactTimeout = transactTimeout;
        this.statusHandler = new StatusHandler() {
            @Override
            public boolean isSuccess(long statusCode) {
                return statusCode == NtStatus.STATUS_PATH_NOT_COVERED.getValue() || wrapped.statusHandler().isSuccess(statusCode);
            }
        };
    }

    @Override
    public <T> T resolve(Session session, SMB2Packet responsePacket, final SmbPath smbPath,
            final ResolveAction<T> action) throws PathResolveException {
        // If the server does not support DFS, short circuit this path resolution.
        if (!session.getConnection().getConnectionContext().supportsDFS()) {
            return wrapped.resolve(session, responsePacket, smbPath, action);
        }

        if (smbPath.getPath() != null && responsePacket.getHeader().getStatusCode() == NtStatus.STATUS_PATH_NOT_COVERED.getValue()) {
            logger.info("DFS Share {} does not cover {}, resolve through DFS", smbPath.getShareName(), smbPath);
            return start(session, smbPath, new ResolveAction<T>() {
                @Override
                public T apply(SmbPath target) {
                    logger.info("DFS resolved {} -> {}", smbPath, target);
                    return action.apply(target);
                }
            });
        } else if (smbPath.getPath() == null && NtStatus.isError(responsePacket.getHeader().getStatusCode())) {
            logger.info("Attempting to resolve {} through DFS", smbPath);
            return start(session, smbPath, action);
        }
        return wrapped.resolve(session, responsePacket, smbPath, action);
    }

    @Override
    public StatusHandler statusHandler() {
        return this.statusHandler;
    }

    @Override
    public <T> T resolve(Session session, SmbPath smbPath, ResolveAction<T> action) throws PathResolveException {
        T target = start(session, smbPath, action);
        if (!smbPath.equals(target)) {
            logger.info("DFS resolved {} -> {}", smbPath, target);
            return target;
        }
        return wrapped.resolve(session, smbPath, action);
    }

    private <T> T start(Session session, SmbPath uncPath, ResolveAction<T> action) throws PathResolveException {
        logger.info("Starting DFS resolution for {}", uncPath.toUncPath());
        DFSPath dfsPath = new DFSPath(uncPath.toUncPath());
        ResolveState<T> state = new ResolveState<T>(dfsPath, action);
        return step1(session, state);
    }

    /**
     * Step 1: If the path has only one path component (for example, \abc), go to step 12; otherwise, go to step 2.
     */
    private <T> T step1(Session session, ResolveState<T> state) throws DFSException {
        logger.trace("DFS[1]: {}", state);
        if (state.path.hasOnlyOnePathComponent() || state.path.isIpc()) { // Also shortcircuit IPC$ connects.
            return step12(state);
        }

        return step2(session, state);
    }

    /**
     * Step 2: Look up the path in ReferralCache if a cache is being maintained.
     * If no cache is being maintained, go to step 5.
     * 1. If no matching entry is found in ReferralCache, go to step 5.
     * 2. If an entry's TTL has expired:
     * - If RootOrLink indicates DFS root targets, goto step 5.
     * - If RootOrLink indicates DFS link targets, goto step 9.
     * 3. If an entry contains DFS link targets as indicated by RootOrLink, go to step 4; otherwise, go to
     * step 3.
     */
    private <T> T step2(Session session, ResolveState<T> state) throws DFSException {
        logger.trace("DFS[2]: {}", state);
        ReferralCache.ReferralCacheEntry lookup = referralCache.lookup(state.path);
        if (lookup == null || (lookup.isExpired() && lookup.isRoot())) {
            return step5(session, state); // Resolve Root Referral
        }
        if (lookup.isExpired()) { // Expired LINK target
            return step9(session, state, lookup); // Resolve Link Referral
        }
        if (lookup.isLink()) {
            return step4(session, state, lookup);
        }
        return step3(session, state, lookup);
    }

    /**
     * Step 3: [ReferralCache hit, unexpired TTL] Replace the portion of the path that matches DFSPathPrefix of the
     * ReferralCache entry with the DFS target path of TargetHint of the ReferralCache entry. For example,
     * if the path is \MyDomain\MyDfs\MyDir and the ReferralCache entry contains \MyDomain\MyDfs with a
     * DFS target path of \someserver\someshare\somepath, the effective path becomes
     * \someserver\someshare\somepath\MyDir. Go to step 8.
     */
    private <T> T step3(Session session, ResolveState<T> state, ReferralCache.ReferralCacheEntry lookup) {
        logger.trace("DFS[3]: {}", state);
        ReferralCache.TargetSetEntry target = lookup.getTargetHint();
        SMBApiException lastException = null;
        DFSPath initialPath = state.path;
        while (target != null) {
            try {
                state.path = state.path.replacePrefix(lookup.getDfsPathPrefix(), lookup.getTargetHint().getTargetPath());
                state.isDFSPath = true;
                return step8(session, state, lookup);
            } catch (SMBApiException e) {
                lastException = e;
                if (e.getStatusCode() != NtStatus.STATUS_PATH_NOT_COVERED.getValue()) {
                    target = lookup.nextTargetHint();
                    state.path = initialPath;
                }
            }
        }

        if (lastException != null) {
            throw lastException;
        }

        throw new IllegalStateException("Unknown error resolving DFS");
    }

    /**
     * Step 4: [ReferralCache hit, unexpired TTL, RootOrLink=link]
     * 1. If the second component of the path is "SYSVOL" or "NETLOGON" go to step 3.
     * 2. Check the Interlink element of the ReferralCache entry.
     * - If Interlink is set in the ReferralCache entry,then the TargetHint is in another DFS namespace. Go to step 11.
     * - If Interlink is not set in the ReferralCache entry then the TargetHint is not in another DFS namespace. Go to step 3.
     */
    private <T> T step4(Session session, ResolveState<T> state, ReferralCache.ReferralCacheEntry lookup) throws DFSException {
        logger.trace("DFS[4]: {}", state);
        if (state.path.isSysVolOrNetLogon()) {
            return step3(session, state, lookup);
        }
        if (lookup.isInterlink()) {
            return step11(session, state, lookup);
        }
        return step3(session, state, lookup);
    }

    /**
     * Step 5: [ReferralCache miss] [ReferralCache hit, expired TTL, RootOrLink=root]
     * Look up the first path component in DomainCache.
     * 1. If no matching DomainCache entry is found, use the first path component as the host name for DFS root referral
     * request purposes. Go to step 6.
     * 2. If a matching DomainCache entry is found:
     * 1. If DCHint is not valid, send DC referral request, as specified in section 3.1.4.2,
     * providing "DC", BootstrapDC, UserCredentials, MaxOutputSizeff, and Path as parameters.
     * The processing of the referral response is specified in section 3.1.5.4.2. If the referral request fails, go to step 13.
     * 2. If the second path component is "SYSVOL" or "NETLOGON", go to step 10.
     * 3. Use DCHint as host name for DFS root referral request purposes. Go to step 6.
     */
    private <T> T step5(Session session, ResolveState<T> state) throws DFSException {
        logger.trace("DFS[5]: {}", state);
        String potentialDomain = state.path.getPathComponents().get(0);
        DomainCache.DomainCacheEntry domainCacheEntry = domainCache.lookup(potentialDomain);
        if (domainCacheEntry == null) { // 5.1
            state.hostName = potentialDomain;
            state.resolvedDomainEntry = false;
            return step6(session, state);
        }

        // 5.2
        if (domainCacheEntry.getDCHint() == null || domainCacheEntry.getDCHint().isEmpty()) { // 5.2.1
            // Send DC referral request
            String bootstrapDC = session.getAuthenticationContext().getDomain();
            // TODO @ckherrmann's code contained extra check resolveState.hostName.equals(bootstrapDC)
            ReferralResult result = sendDfsReferralRequest(DfsRequestType.DC, bootstrapDC, session, state.path); // TODO
            if (!NtStatus.isSuccess(result.status)) {
                return step13(session, state, result);
            }
            domainCacheEntry = result.domainCacheEntry;
        }

        if (state.path.isSysVolOrNetLogon()) { // 5.2.2
            return step10(session, state, domainCacheEntry);
        }

        // 5.2.3
        state.hostName = domainCacheEntry.getDCHint();
        state.resolvedDomainEntry = true;
        return step6(session, state);
    }

    /**
     * [DFS Root referral request] Issue a DFS root referral request, as specified in section 3.1.4.2,
     * providing "ROOT", the first path component, UserCredentials, MaxOutputSize, and Path as parameters.
     * The processing of the referral response and/or error is as specified in section 3.1.5.4.3, which will update the ReferralCache
     * on success. On DFS root referral request success, go to step 7.
     * On DFS root referral request failure:
     * 1. If the immediately preceding processing step was step 5.2.3, this is a domain name or path. Go to step 13.
     * 2. If processing of this I/O request encountered a ReferralCache hit, or one of its DFS referral requests succeeded
     * (as would have occurred in the case of a previous Interlink - see step 11 - or a domain root referral,
     * when entering from step 5), the path is in a DFS namespace. Go to step 14.
     * 3. The path is not a DFS path and no further processing is required. Go to step 12.
     */
    private <T> T step6(Session session, ResolveState<T> state) throws DFSException {
        logger.trace("DFS[6]: {}", state);
        ReferralResult result = sendDfsReferralRequest(DfsRequestType.ROOT, state.path.getPathComponents().get(0), session, state.path);
        if (NtStatus.isSuccess(result.status)) {
            return step7(session, state, result.referralCacheEntry);
        }

        if (state.resolvedDomainEntry) { // Came from 5.2.3
            return step13(session, state, result);
        }
        if (state.isDFSPath) {
            return step14(session, state, result);
        }

        return step12(state);
    }

    /**
     * [DFS root referral success] If the current ReferralCache entry's RootOrLink indicates
     * root targets, go to step 3; otherwise, go to step 4.
     */
    private <T> T step7(Session session, ResolveState<T> state, ReferralCache.ReferralCacheEntry lookup) throws DFSException {
        logger.trace("DFS[7]: {}", state);
        if (lookup.isRoot()) {
            return step3(session, state, lookup);
        }
        return step4(session, state, lookup);
    }

    /**
     * Step 8: [I/O request, path fully resolved] Issue I/O operation to TargetHint of ReferralCache entry.
     * 1. If the I/O operation fails with STATUS_PATH_NOT_COVERED.
     * - If the RootOrLink of ReferralCache entry indicates link targets, set the failure status to the last error that occurred and go to step 14.
     * - If the RootOrLink of ReferralCache entry indicates root targets, the process is as specified in section 3.1.5.1.
     * If this processing does not successfully determine a ReferralCache entry to traverse the link, set the failure status
     * to the last error that occurred and go to step 14.
     * - ReferralCache entry for the link determined successfully. Go to step 4.
     * 2. If the I/O operation fails with an error other than STATUS_PATH_NOT_COVERED, then the process is as specified in section 3.1.5.2.
     * If the processing of that section specifies a new TargetHint, repeat step 8. Otherwise, set the failure status to the last error that
     * occurred and go to step 14.
     * 3. If the I/O operation is successful, the process is as specified in section 3.1.5.3. Complete the I/O operation and
     * user/application-initiated I/O request with success.
     */
    @SuppressWarnings("PMD.UnusedFormalParameter")
    private <T> T step8(Session session, ResolveState<T> state, ReferralCache.ReferralCacheEntry lookup) {
        logger.trace("DFS[8]: {}", state);
        return state.action.apply(SmbPath.parse(state.path.toPath()));
    }

    /**
     * Step 9: [ReferralCache hit, expired TTL, RootOrLink=link] The link referral request is issued to a DFS root target of the namespace.
     * Find the root ReferralCache entry corresponding to the first two path components, noting that this will already be in the cache due
     * to processing that resulted in acquiring the expired link ReferralCache entry. Issue a DFS link referral request,
     * as specified in section 3.1.4.2, providing "LINK", TargetHint of the root ReferralCache entry, UserCredentials, MaxOutputSize, and Path
     * as parameters, and process the DFS referral response and/or error as specified in section 3.1.5.4.3, which will update the ReferralCache
     * on success.
     * <p>
     * If the DFS Link referral request fails, set the failure status to the last error that occurred and go to step 14. Otherwise:
     * 1. If the RootOrLink of the refreshed ReferralCache entry indicates DFS root targets, go to step 3.
     * 2. If the RootOrLink of the refreshed ReferralCache entry indicates DFS link targets, go to step 4.
     */
    @SuppressWarnings("PMD.UnusedFormalParameter")
    private <T> T step9(Session session, ResolveState<T> state, ReferralCache.ReferralCacheEntry lookup) throws DFSException {
        logger.trace("DFS[9]: {}", state);
        DFSPath rootPath = new DFSPath(state.path.getPathComponents().subList(0, 2));
        ReferralCache.ReferralCacheEntry rootReferralCacheEntry = referralCache.lookup(rootPath);
        if (rootReferralCacheEntry == null) {
            logger.debug("Could not find referral cache entry for {}", rootPath);
            referralCache.clear(state.path);
            return step1(session, state);
        }
        ReferralResult result = sendDfsReferralRequest(DfsRequestType.LINK, rootReferralCacheEntry.getTargetHint().getTargetPath().getPathComponents().get(0), session, state.path);
        if (!NtStatus.isSuccess(result.status)) {
            return step14(session, state, result);
        }

        if (result.referralCacheEntry.isRoot()) {
            return step3(session, state, result.referralCacheEntry);
        }

        return step4(session, state, result.referralCacheEntry);
    }

    /**
     * Step 10: [sysvol referral request] Issue a sysvol referral request, as specified in
     * section 3.1.4.2, providing 'SYSVOL', the DCHint DC of the DomainCache entry that
     * corresponds to the domain name in the first path component, UserCredentials, MaxOutputSize,
     * and Path as parameters. The processing of the referral response and/or error is as
     * specified in section 3.1.5.4.4, which will update the ReferralCache on success.
     * If the referral request is successful, go to step 3; otherwise, go to step 13.
     */
    private <T> T step10(Session session, ResolveState<T> state, DomainCache.DomainCacheEntry domainCacheEntry) throws DFSException {
        logger.trace("DFS[10]: {}", state);
        ReferralResult r = sendDfsReferralRequest(DfsRequestType.SYSVOL, domainCacheEntry.getDCHint(), session, state.path);
        if (NtStatus.isSuccess(r.status)) {
            return step3(session, state, r.referralCacheEntry);
        }
        return step13(session, state, r);
    }

    /**
     * Step 11: [interlink] Replace the portion of the path that matches the DFSPathPrefix of
     * the ReferralCache entry with TargetHint. For example, if the path is \MyDomain\MyDfs\MyLink\MyDir
     * and the referral entry contains \MyDomain\MyDfs\MyLink with a DFS target path of
     * \someserver\someshare\somepath, the effective path becomes
     * \someserver\someshare\somepath\MyDir. Go to step 2.
     */
    private <T> T step11(Session session, ResolveState<T> state, ReferralCache.ReferralCacheEntry lookup) throws DFSException {
        logger.trace("DFS[11]: {}", state);
        state.path = state.path.replacePrefix(lookup.getDfsPathPrefix(), lookup.getTargetHint().getTargetPath());
        state.isDFSPath = true;
        return step2(session, state);
    }

    /**
     * Step 12: [not DFS] The path does not correspond to a DFS namespace or a SYSVOL/NETLOGON share.
     * Do not change the path, and return an implementation-defined error.
     * The user/application initiated I/O request is handled by the local operating system.
     */
    private <T> T step12(ResolveState<T> state) {
        logger.trace("DFS[12]: {}", state);
        return state.action.apply(SmbPath.parse(state.path.toPath()));
    }

    /**
     * Step 13: [Cannot get DC for domain] The first path component is a domain name.
     * Fail the I/O operation and user/application-initiated I/O request with the last
     * error code that occurred before the jump to this step.
     */
    @SuppressWarnings("PMD.UnusedFormalParameter")
    private <T> T step13(Session session, ResolveState<T> state, ReferralResult result) throws DFSException {
        logger.trace("DFS[13]: {}", state);
        throw new DFSException(result.status, "Cannot get DC for domain '" + state.path.getPathComponents().get(0) + "'");
    }

    /**
     * Step 14: [DFS path] The path is known to be in a DFS namespace, but the DFS root referral
     * request or DFS Link referral request has failed. Complete the user/application-initiated
     * I/O request with the error code that occurred before the jump to this step.
     */
    @SuppressWarnings("PMD.UnusedFormalParameter")
    private <T> T step14(Session session, ResolveState<T> state, ReferralResult result) throws DFSException {
        logger.trace("DFS[14]: {}", state);
        throw new DFSException(result.status, "DFS request failed for path " + state.path);
    }

    private ReferralResult sendDfsReferralRequest(DfsRequestType type, String hostName, Session session, DFSPath path) throws DFSException {
        // The client MUST initiate a server session with the SMB server, as specified in [MS-CIFS] section 3.4.4.7,
        // by passing HostName and UserCredentials as input parameters and receiving an opaque ClientGenericContext,
        // as specified in [MS-CIFS] section 3.4.
        // The client MUST search for an existing Session and TreeConnect to any share on the server identified by
        // ServerName for the user identified by UserCredentials. If no Session and TreeConnect are found, the client
        // MUST establish a new Session and TreeConnect to IPC$ on the target server as described in section 3.2.4.2
        // using the supplied ServerName and UserCredentials
        Session dfsSession = session;
        if (!hostName.equals(session.getConnection().getRemoteHostname())) {
            AuthenticationContext auth = session.getAuthenticationContext();
            Connection oldConnection = session.getConnection();
            Connection connection;
            try {
                connection = oldConnection.getClient().connect(hostName); // TODO
            } catch (IOException e) {
                throw new DFSException(e);
            }
            dfsSession = connection.authenticate(auth);
        }

        try {
            Share dfsShare = dfsSession.connectShare("IPC$"); // explicitly not closed as we want to re-use the cached Share for multiple requests
            return getReferral(type, dfsShare, path);
        } catch (Buffer.BufferException | IOException e) {
            throw new DFSException(e);
        }
    }

    private ReferralResult getReferral(DfsRequestType type, Share share, DFSPath path) throws TransportException, Buffer.BufferException {
        SMB2GetDFSReferralRequest req = new SMB2GetDFSReferralRequest(path.toPath());
        SMBBuffer buffer = new SMBBuffer();
        req.writeTo(buffer);
        Future<SMB2IoctlResponse> ioctl = share.ioctlAsync(FSCTL_DFS_GET_REFERRALS, true, new BufferByteChunkProvider(buffer));
        SMB2IoctlResponse response = Futures.get(ioctl, transactTimeout, TimeUnit.MILLISECONDS, TransportException.Wrapper);
        return handleReferralResponse(type, response, path);

    }

    private ReferralResult handleReferralResponse(DfsRequestType type, SMB2IoctlResponse response, DFSPath originalPath) throws Buffer.BufferException {
        ReferralResult result = new ReferralResult(response.getHeader().getStatusCode());
        if (result.status == NtStatus.STATUS_SUCCESS.getValue()) {
            SMB2GetDFSReferralResponse resp = new SMB2GetDFSReferralResponse(originalPath.toPath());
            resp.read(new SMBBuffer(response.getOutputBuffer()));

            switch (type) {
                case DC:
                    handleDCReferralResponse(result, resp);
                    break;
                case DOMAIN:
                    throw new UnsupportedOperationException(DfsRequestType.DOMAIN + " not used yet.");
                case SYSVOL:
                case ROOT:
                case LINK:
                    handleRootOrLinkReferralResponse(result, resp);
                    break;
                default:
                    throw new IllegalStateException("Encountered unhandled DFS RequestType: " + type);
            }
        }
        return result;
    }

    private void handleRootOrLinkReferralResponse(ReferralResult result, SMB2GetDFSReferralResponse response) {
        if (response.getReferralEntries().isEmpty()) {
            result.status = NtStatus.STATUS_OBJECT_PATH_NOT_FOUND.getValue();
            return;
        }
        ReferralCache.ReferralCacheEntry referralCacheEntry = new ReferralCache.ReferralCacheEntry(response, domainCache);
        logger.info("Got DFS Referral result: {}", referralCacheEntry);
        referralCache.put(referralCacheEntry);
        result.referralCacheEntry = referralCacheEntry;
    }

    private void handleDCReferralResponse(ReferralResult result, SMB2GetDFSReferralResponse response) {
        if (response.getVersionNumber() < 3) {
            return;
        }
        DomainCache.DomainCacheEntry domainCacheEntry = new DomainCache.DomainCacheEntry(response);
        domainCache.put(domainCacheEntry);
        result.domainCacheEntry = domainCacheEntry;
    }

    private static class ResolveState<T> {
        final ResolveAction<T> action;
        DFSPath path;
        boolean resolvedDomainEntry = false;
        boolean isDFSPath = false;
        String hostName = null;

        ResolveState(DFSPath path, ResolveAction<T> action) {
            this.path = path;
            this.action = action;
        }

        @Override
        public String toString() {
            return "ResolveState{" +
                "path=" + path +
                ", resolvedDomainEntry=" + resolvedDomainEntry +
                ", isDFSPath=" + isDFSPath +
                ", hostName='" + hostName + '\'' +
                '}';
        }
    }

    private static class ReferralResult {
        long status;
        ReferralCache.ReferralCacheEntry referralCacheEntry;
        DomainCache.DomainCacheEntry domainCacheEntry;

        private ReferralResult(long status) {
            this.status = status;
        }

        private ReferralResult(ReferralCache.ReferralCacheEntry referralCacheEntry) {
            this.referralCacheEntry = referralCacheEntry;
        }

        private ReferralResult(DomainCache.DomainCacheEntry domainCacheEntry) {
            this.domainCacheEntry = domainCacheEntry;
        }
    }
}
