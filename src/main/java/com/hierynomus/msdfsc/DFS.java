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
package com.hierynomus.msdfsc;

import java.io.IOException;
import java.util.concurrent.Future;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.msdfsc.DomainCache;
import com.hierynomus.msdfsc.DomainCache.DomainCacheEntry;
import com.hierynomus.msdfsc.ReferralCache.ReferralCacheEntry;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.messages.SMB2CreateRequest;
import com.hierynomus.mssmb2.messages.SMB2IoctlRequest;
import com.hierynomus.mssmb2.messages.SMB2IoctlResponse;
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.Share;
import com.hierynomus.smbj.share.TreeConnect;
import com.hierynomus.smbj.transport.TransportException;

public class DFS {
    private static final Logger logger = LoggerFactory.getLogger(DFS.class);

    ReferralCache referralCache = new ReferralCache();
    DomainCache domainCache = new DomainCache();
    static DFS dfs = new DFS();
    
    class ResolveState {
        boolean isDomainOrPath = false;
        boolean isDFSPath = false;
        String hostName = null;
        String path;

        ResolveState(String path) {
            this.path = path;
        }
    }
    
    public static void resolveDFS(Session session, SmbPath path) throws DFSException {
        String newPath;
        try {
            newPath = dfs.resolvePath(session, path.toString());
            path.parse(newPath);
        } catch (IOException | BufferException e) {
            // just return the old path back.
            logger.error("Exception processing DFS", e);
            throw new DFSException(e);
        }
    }
    
    public static void resolvePathNotCoveredError(Session session, SMB2CreateRequest packet) throws DFSException {
        try {
        // See [MS-DFSC] 3.1.5.1 I/O Operation to Target Fails with STATUS_PATH_NOT_COVERED
            packet.setFileName(dfs.resolvePath(session, packet.getFileName()));
        } catch (IOException | BufferException e) {
            // just return the old path back.
            logger.error("Exception processing DFS", e);
            throw new DFSException(e);
        }
    }

    // called when requesting a path before an operation
    String resolvePath(Session session, String pathToResolve) throws IOException, BufferException, DFSException {
        ReferralCache.ReferralCacheEntry referralCacheEntry = null;

        String npath = normalizePath(pathToResolve);
        final String[] pathEntries = parsePath(npath); 
        ResolveState resolveState = new ResolveState(npath);
        
        if (referralCache == null) {
            return resolveState.path; // no referral cache means no referrals
        }

// 1. If the path has only one path component (for example, \abc), go to step 12; otherwise, go to step 2.
        if (pathEntries.length == 1) {
            return resolveState.path; // step12: return the original path
        }
        if (pathEntries[1].equals("IPC$")) { // ignore IPC$, that's magic
            return resolveState.path;
        }

        while(resolveState.path != null) {
// 2. Look up the path in ReferralCache if a cache is being maintained. If no cache is being maintained, go to step 5.
//      1. If no matching entry is found in ReferralCache, go to step 5.
//      2. If an entry's TTL has expired:
//        - If RootOrLink indicates DFS root targets, go to step 5.
//        - If RootOrLink indicates DFS link targets, go to step 9.
//      3. If an entry contains DFS link targets as indicated by RootOrLink, go to step 4; otherwise, go to step 3.
            if (referralCacheEntry == null) {
                referralCacheEntry = referralCache.lookup(resolveState.path);
            }
            if (referralCacheEntry == null || (referralCacheEntry.isExpired() && referralCacheEntry.isRoot())) {
                referralCacheEntry = resolveRoot(session, referralCacheEntry, resolveState.path, pathEntries, resolveState);
            } else if (referralCacheEntry.isExpired() && referralCacheEntry.isLink()) {
                referralCacheEntry = resolveLink(session, resolveState.path, pathEntries);
            }

            if (referralCacheEntry == null) {
                if (resolveState.hostName == null) {
                    throw new IllegalStateException("Not expecting hostName to be null");
                }
                referralCacheEntry = resolveFromHost(session, referralCacheEntry, resolveState);
            }

            // process the referral cache entry we ended up with
            if (referralCacheEntry != null) {
                resolveState.isDFSPath = true; // remember that the path contained at least one DFS translation

// 4. [ReferralCache hit, unexpired TTL, RootOrLink=link]
//   1. If the second component of the path is "SYSVOL" or "NETLOGON" go to step 3.
//   2. Check the Interlink element of the ReferralCache entry.
//     - If Interlink is set in the ReferralCache entry, then the TargetHint is in another DFS namespace. 
//       Go to step 11.
//     - If Interlink is not set in the ReferralCache entry then the TargetHint is not in another 
//       DFS namespace. Go to step 3.
                if (referralCacheEntry.isInterlink() && !"SYSVOL".equals(pathEntries[1]) && !"NETLOGON".equals(pathEntries[1])) {
//    11. [interlink] Replace the portion of the path that matches the DFSPathPrefix of the ReferralCache entry with TargetHint. 
//    For example, if the path is \MyDomain\MyDfs\MyLink\MyDir and the referral entry contains \MyDomain\MyDfs\MyLink 
//    with a DFS target path of \someserver\someshare\somepath, the effective path becomes \someserver\someshare\somepath\MyDir. 
//    Go to step 2.
                    resolveState.path = referralCacheEntry.targetHint.targetPath + resolveState.path.substring(referralCacheEntry.dfsPathPrefix.length());
                    continue;
                } else {

// 3. [ReferralCache hit, unexpired TTL] Replace the portion of the path that matches DFSPathPrefix 
// of the ReferralCache entry with the DFS target path of TargetHint of the ReferralCache entry. 
// For example, if the path is \MyDomain\MyDfs\MyDir and the ReferralCache entry contains 
// \MyDomain\MyDfs with a DFS target path of \someserver\someshare\somepath, the effective 
// path becomes \someserver\someshare\somepath\MyDir. Go to step 8.
                    resolveState.path = referralCacheEntry.targetHint.targetPath + 
                                ((resolveState.path.length() > referralCacheEntry.dfsPathPrefix.length()) ? 
                                        resolveState.path.substring(referralCacheEntry.dfsPathPrefix.length()) : "");
                    //TODO should open transport/session/treeConnect to that server
                    return resolveState.path;
                }
            }
        }
        return resolveState.hostName;
    }

    private ReferralCache.ReferralCacheEntry resolveFromHost(Session session, ReferralCache.ReferralCacheEntry referralCacheEntry,
            ResolveState resolveState) throws IOException, BufferException, DFSException {
// 6. [DFS Root referral request] Issue a DFS root referral request, as specified in section 3.1.4.2, providing "ROOT", 
//     the first path component, UserCredentials, MaxOutputSize, and Path as parameters. The processing of the referral 
//     response and/or error is as specified in section 3.1.5.4.3, which will update the ReferralCache on success. 
//     On DFS root referral request success, go to step 7. 
//     On DFS root referral request failure:
//     1. If the immediately preceding processing step was step 5, this is a domain name or path. Go to step 13.
//     2. If processing of this I/O request encountered a ReferralCache hit, or one of its DFS referral requests 
//        succeeded (as would have occurred in the case of a previous Interlink - see step 11 - or a domain root 
//        referral, when entering from step 5), the path is in a DFS namespace. Go to step 14.
//     3. The path is not a DFS path and no further processing is required. Go to step 12.
            ReferralResult r = sendReferralRequest("ROOT", resolveState.hostName, session, resolveState.path);

            if (r.error == NtStatus.STATUS_SUCCESS) {
                resolveState.isDFSPath = true; // remember that the path contained at least one DFS translation
// 7. [DFS root referral success] If the current ReferralCache entry's RootOrLink indicates root targets, go to step 3; 
//       otherwise, go to step 4.
                referralCacheEntry = r.referralCacheEntry;
            } else {
                if (!resolveState.isDomainOrPath && !resolveState.isDFSPath) { 
                    //path is not a dfs path
                    resolveState.hostName = resolveState.path;
                    
                    return null; // step12: return the original path
                }
                else {
                    throw new DFSException(r.error); // step13/14: fail with error
                }
            }
        return referralCacheEntry;
    }

    private ReferralCache.ReferralCacheEntry resolveLink(Session session, String path, final String[] pathEntries) throws IOException,
            BufferException, DFSException {
        ReferralCache.ReferralCacheEntry referralCacheEntry;
//  9. [ReferralCache hit, expired TTL, RootOrLink=link] The link referral request is issued to a DFS root target of the namespace.
//  Find the root ReferralCache entry corresponding to the first two path components, noting that this will already be 
//  in the cache due to processing that resulted in acquiring the expired link ReferralCache entry. Issue a DFS link referral 
//  request, as specified in section 3.1.4.2, providing "LINK", TargetHint of the root ReferralCache entry, UserCredentials,
//  MaxOutputSize, and Pathf as parameters, and process the DFS referral response and/or error as specified in section 3.1.5.4.3, 
//  which will update the ReferralCache on success. If the DFS Link referral request fails, set the failure status to the last 
//  error that occurred and go to step 14. 
//  Otherwise:
//    1. If the RootOrLink of the refreshed ReferralCache entry indicates DFS root targets, go to step 3.
//    2. If the RootOrLink of the refreshed ReferralCache entry indicates DFS link targets, go to step 4.
        referralCacheEntry = referralCache.lookup("\\"+pathEntries[0]+"\\"+pathEntries[1]);
        if (referralCacheEntry == null) {
            throw new IllegalStateException("Missing referral cache entry for "+"\\"+pathEntries[0]+"\\"+pathEntries[1]);
        }
        ReferralResult r = sendReferralRequest("LINK", referralCacheEntry.targetHint.targetPath, session, path );
        if (r.error != NtStatus.STATUS_SUCCESS) {
            throw new DFSException(r.error); // step14: fail with error
        }
        return referralCacheEntry;
    }

    private ReferralCache.ReferralCacheEntry resolveRoot(Session session, ReferralCache.ReferralCacheEntry referralCacheEntry, String path,
            final String[] pathEntries, ResolveState resolveState) throws IOException, BufferException, DFSException {
        DomainCache.DomainCacheEntry domainCacheEntry;
// 5. [ReferralCache miss] [ReferralCache hit, expired TTL, RootOrLink=root] Look up the first path component in DomainCache.
//   1. If no matching DomainCache entry is found, use the first path component as the host name for DFS root referral 
//      request purposes. Go to step 6.
//   2. If a matching DomainCache entry is found:
//     1. If DCHint is not valid, send DC referral request, as specified in section 3.1.4.2, providing "DC", 
//        BootstrapDC, UserCredentials, MaxOutputSizeff, and Path as parameters. The processing of the referral 
//        response is specified in section 3.1.5.4.2. If the referral request fails, go to step 13.
//     2. If the second path component is "SYSVOL" or "NETLOGON", go to step 10.
//     3. Use DCHint as host name for DFS root referral request purposes.
        domainCacheEntry = domainCache.lookup(pathEntries[0]);
        if (domainCacheEntry == null || domainCacheEntry.DCHint == null || domainCacheEntry.DCHint.isEmpty()) {
            // use the first path component as the host name for DFS root referral
            String bootstrapDC = session.getAuthenticationContext().getDomain();
            resolveState.hostName = pathEntries[0];
            if (resolveState.hostName.equals(bootstrapDC)) {
                // we will send the domain referral request to the user's domain
                ReferralResult r = sendReferralRequest("DC", bootstrapDC, session, pathEntries[0]);
                if (r.error != NtStatus.STATUS_SUCCESS) {
                    throw new DFSException(r.error); // step13: fail with error
                }
                domainCacheEntry = r.domainCacheEntry;
            }
            resolveState.isDomainOrPath = true;
        }
        if (domainCacheEntry != null) { // domainCacheEntry found
            resolveState.isDFSPath = true; // remember that the path contained at least one DFS translation

            if ("SYSVOL".equals(pathEntries[1]) || "NETLOGON".equals(pathEntries[1])) {
// 10. [sysvol referral request] Issue a sysvol referral request, as specified in section 3.1.4.2, providing 'SYSVOL', 
// the DCHint DC of the DomainCache entry that corresponds to the domain name in the first path component, UserCredentials, 
// MaxOutputSize, and Path as parameters. 
// The processing of the referral response and/or error is as specified in 
// section 3.1.5.4.4, which will update the ReferralCache on success. 
// If the referral request is successful, go to step 3; 
// otherwise, go to step 13.
                ReferralResult r = sendReferralRequest("SYSVOL", domainCacheEntry.DCHint, session, path ); 
                if (r.error == NtStatus.STATUS_SUCCESS) {
                    referralCacheEntry = r.referralCacheEntry;
                } else {
                    throw new DFSException(r.error); // step13: fail with error
                }
            } else {
                // use dchint as hostname for dfs root referral purposes
                resolveState.hostName = domainCacheEntry.DCHint;
                resolveState.isDomainOrPath = true;
                //                goto step6;
            }
        }
        return referralCacheEntry;
    }
    
// The client MUST initiate a server session with the SMB server, as specified in [MS-CIFS] section 3.4.4.7, 
// by passing HostName and UserCredentials as input parameters and receiving an opaque ClientGenericContext, 
// as specified in [MS-CIFS] section 3.4.
    ReferralResult sendReferralRequest(String type, String hostName, Session session, String path) throws IOException, BufferException {
// The client MUST search for an existing Session and TreeConnect to any share on the server identified by 
// ServerName for the user identified by UserCredentials. If no Session and TreeConnect are found, the client 
// MUST establish a new Session and TreeConnect to IPC$ on the target server as described in section 3.2.4.2 
// using the supplied ServerName and UserCredentials
        Connection connection;
        Session dfsSession;
        ReferralResult result;
        
        if (hostName.equals(session.getConnection().getRemoteHostname())) {
            dfsSession = session;
            Share dfsShare = dfsSession.connectShare("IPC$");
            result = getReferral(type, dfsShare.getTreeConnect(), path);
        } else {
            AuthenticationContext auth = session.getAuthenticationContext();
            Connection oldConnection = session.getConnection();
            connection = oldConnection.getClient().connect(hostName, oldConnection.getRemotePort());
            dfsSession = connection.authenticate(auth);
            Share dfsShare = dfsSession.connectShare("IPC$");
            result = getReferral(type, dfsShare.getTreeConnect(), path);
        }
        return result;
//TODO do we close the share?
    }

    // Execute a FSCTL_DFS_GET_REFERRALS_EX
    ReferralResult getReferralEx(String type, TreeConnect treeConnect, String path) throws TransportException, BufferException {
        SMBBuffer buffer = new SMBBuffer();
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        SMB2GetDFSReferralEx dfsRequest = new SMB2GetDFSReferralEx( path );
        dfsRequest.writeTo(buffer);
        SMB2IoctlRequest msg = new SMB2IoctlRequest(
                        connection.getNegotiatedProtocol().getDialect(), session.getSessionId(), treeConnect.getTreeId(),
                        SMB2IoctlRequest.ControlCode.FSCTL_DFS_GET_REFERRALS_EX, new SMB2FileId(), 
                        buffer.getCompactData(), true); //TODO remove the getCompactData, that is wasteful

        Future<SMB2IoctlResponse> sendFuture = session.send(msg);
        SMB2IoctlResponse response = Futures.get(sendFuture, TransportException.Wrapper);

        if (response.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(response.getHeader(), "GetDFSReferralEx failed for " + path);
        }
        return processReferralResponse(type, response, path);
    }

    // Execute a FSCTL_DFS_GET_REFERRALS
    ReferralResult getReferral(String type, TreeConnect treeConnect, String path) throws TransportException, BufferException {
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        SMB2GetDFSReferral req = new SMB2GetDFSReferral( path );
        SMBBuffer buffer = new SMBBuffer();
        req.writeTo(buffer);
        SMB2IoctlRequest msg = new SMB2IoctlRequest(
                        connection.getNegotiatedProtocol().getDialect(), session.getSessionId(), treeConnect.getTreeId(),
                        SMB2IoctlRequest.ControlCode.FSCTL_DFS_GET_REFERRALS, new SMB2FileId(),
                        buffer.getCompactData(), true);

        Future<SMB2IoctlResponse> sendFuture = session.send(msg);
        SMB2IoctlResponse response = Futures.get(sendFuture, TransportException.Wrapper);
        return processReferralResponse(type, response, path);
    }

    ReferralResult processReferralResponse(String type, SMB2IoctlResponse message, String originalPath) throws BufferException {
        ReferralResult result = new ReferralResult();
        result.error = message.getHeader().getStatus();
        if (message.getHeader().getStatus() == NtStatus.STATUS_SUCCESS) {
            SMB2GetDFSReferralResponse resp = new SMB2GetDFSReferralResponse(originalPath);
            resp.read(new SMBBuffer(message.getOutputBuffer()));

            if ("DC".equals(type)) {
                DomainCacheEntry domainCacheEntry = domainCache.new DomainCacheEntry(resp);
                domainCache.put(domainCacheEntry);
                result.domainCacheEntry = domainCacheEntry;
            } else {
                ReferralCacheEntry referralCacheEntry = referralCache.new ReferralCacheEntry(resp);
                referralCache.put(referralCacheEntry);
                result.referralCacheEntry = referralCacheEntry;
            }
        }
        return result;
    }

    // [MS-DFSC] 2.2.1 Common Conventions
    // All paths in REQ_GET_DFS_REFERRAL and RESP_GET_DFS_REFERRAL messages MUST be encoded with exactly one 
    // leading backslash, not two leading backslashes as is common to user-visible UNC paths. For example, 
    // the UNC path "\\server\namespace\directory\subdirectory\file" would be encoded 
    // as "\server\namespace\directory\subdirectory\file".
    static String normalizePath(String path) {
        String newPath;
        if (path.startsWith("\\\\")) { // if starts with two backslashes
            newPath = path.substring(1);  // remove the first backslash
        } else {
            newPath = path;
        }
        return newPath;
    }

    /**
     * split a path of the form "\a\b\c\d" into an array of strings: {"a", "b", "c", "d"}
     * @param path
     * @return the array of Strings with the path elements
     */
    static String[] parsePath(String path) {
        if (path.startsWith("\\\\")) {
            return path.substring(2).split("\\\\"); // this is a regex, so it means "split on single backslash"
        } else if (path.startsWith("\\")) {
            return path.substring(1).split("\\\\"); // this is a regex, so it means "split on single backslash"
        } else {
            return path.split("\\\\"); // this is a regex, so it means "split on single backslash"
        }
    }

    class ReferralResult {
        NtStatus error;
        ReferralCacheEntry referralCacheEntry;
        DomainCacheEntry domainCacheEntry;
    }
    
    public static void clearCaches() {
        dfs.referralCache.clear();
        dfs.domainCache.clear();
    }

}
