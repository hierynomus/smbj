package com.hieronymus.mssmb2.dfs;

import java.util.concurrent.Future;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.messages.SMB2CreateResponse;
import com.hierynomus.mssmb2.messages.SMB2IoctlRequest;
import com.hierynomus.mssmb2.messages.SMB2IoctlResponse;
import com.hierynomus.mssmb2.messages.SMB2ReadRequest;
import com.hierynomus.mssmb2.messages.SMB2IoctlRequest.ControlCode;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.TreeConnect;
import com.hierynomus.smbj.transport.TransportException;

public class DFS {
    // called when requesting a path
    public String resolvePath(String path) {
        path = normalizePath(path);
        // TODO validate path? must contain 2 components (servername\share) at least
        if (one path component?) {
          //12
        } else {
            //2
            // look in referral cache
            DFSReferral referral = referralCache.lookup(path);
            if (referral != null) {
                if referral.ttl expired {
                    if (referral.rootOrLInk==root) {
                        //5
                        DFSReferral domainReferral = domainCache.lookup(path.entries[0]);
                        if (domainReferral != null) {
                            if (dc hint is valid) {
                                if (path[1]=="sysvol" || path[1]=="netlogon") {
                                    //10
                                }
                                else {
                                    use dchint as hostname for dfs root referral purposes
                                }
                            } else {
                                
                            }
                            
                        }
                        else {
                            
                            //6
                        }
                        
                    } else {
                        //9
                    }
                } else {
                    if (referral.rootOrLink==root) {
                        //3
                        replacePathPortion(path,referral.dfsPathPrefix,referral.targetHint);
                        //8
                        try operation to targetHint
                        if fail not covered {
                            //
                            if (referral.rootOrLink==root) {
                                cover.
                            } else {
                                
                            }
                            
                        } else {
                            if fail {
                                return io/fail code
                            } else {
                                complete?
                            }
                        }
                        
                        
                    } else {
                        //4
                        if (path[1]==sysvol || path[1]==netlogon) {
                            //3
                        }
                        else if (referral.interlink) {
                            //11
                        }
                        else {
                            //3
                        }
                    }
                }
            }
            else {
                //5
            }
            
        }
                        
    }
    
    // called when STATUS_PATH_NOT_COVERED returned
    public String coverPath(String path) {
        
    }
    
    // Execute a FSCTL_DFS_GET_REFERRALS_EX
    public DFSReferral getReferralEx(TreeConnect treeConnect, String path) {
        SMBBuffer buffer = new SMBBuffer();
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        SMB2GetDFSReferralEx dfsRequest = new SMB2GetDFSReferralEx( path );
        dfsRequest.writeTo(buffer);
        SMB2IoctlRequest msg = new SMB2IoctlRequest(
                        connection.getNegotiatedProtocol().getDialect(), session.getSessionId(), treeConnect.getTreeId(),
                        SMB2IoctlRequest.ControlCode.FSCTL_DFS_GET_REFERRALS_EX, null,//TODO: is this corerct 
                        buffer.getCompactData(), true); //TODO remove the getCompactData, that is wasteful

        Future<SMB2IoctlResponse> sendFuture = session.send(msg);
        SMB2IoctlResponse msgResp = Futures.get(sendFuture, TransportException.Wrapper);
        
        if (msgResp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(msgResp.getHeader(), "GetDFSReferralEx failed for " + path);
        }
        SMB2GetDFSReferralResponse resp = new SMB2GetDFSReferralResponse(msgResp.data());

        return new DFSReferral(resp);
    }
    
    // Execute a FSCTL_DFS_GET_REFERRALS
    public static DFSReferral getReferral(TreeConnect treeConnect, String path) {
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        SMB2GetDFSReferralEx req = new SMB2GetDFSReferral( path );
        SMB2IoctlRequest msg = new SMB2IoctlRequest(
                        connection.getNegotiatedProtocol(), session.getSessionId(), treeConnect,
                        SMB2IoctlRequest.ControlCode.FSCTL_DFS_GET_REFERRALS, 0,
                        req.data(), true);
                    );
        Future<SMB2IoctlResponse> msgResp = session.send(msg);
        SMB2GetDFSReferralResponse resp = new SMB2GetDFSReferralResponse(msgResp.data());
        return new DFSReferral(resp);
    }
    
    // [MS-DFSC] 2.2.1 Common Conventions
    // All paths in REQ_GET_DFS_REFERRAL and RESP_GET_DFS_REFERRAL messages MUST be encoded with exactly one 
    // leading backslash, not two leading backslashes as is common to user-visible UNC paths. For example, 
    // the UNC path "\\server\namespace\directory\subdirectory\file" would be encoded 
    // as "\server\namespace\directory\subdirectory\file".
    String normalizePath(String path) {
        if (path.startsWith("\\\\")) {
            path = path.substring(1);
        }
        return path;
    }
}
