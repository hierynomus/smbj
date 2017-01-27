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

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.isSet;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import com.hierynomus.msdfsc.SMB2GetDFSReferralResponse.ReferralHeaderFlags;

/**
 * [MS-DFSC].pdf: 3.1.1 Abstract Data Model
 * <p>
 * ReferralCache: This cache contains root, link, and sysvol referral responses.
 * A hit on a ReferralCache entry indicates that the path in a name resolution
 * operation is a DFS Root, DFS link, or a SYSVOL/NETLOGON share. A
 * ReferralCache entry conceptually contains entries indexed by a DFS path
 * prefix, DFSPathPrefix. An entry is a tuple of the form <DFSPathPrefix,
 * RootOrLink, Interlink, TTL, TargetFailback, TargetHint, TargetList>.
 * DFSPathPrefix is the DFS path that corresponds to a DFS root or a DFS link,
 * and is the same as the string pointed to by the DFSPathOffset of a
 * DFS_REFERRAL_V2, DFS_REFERRAL_V3 or DFS_REFERRAL_V4 referral entry.
 * RootOrLink identifies whether the entry contains DFS root targets or DFS link
 * targets. It reflects the value from the ServerType field of a referral entry
 * (as specified in sections 2.2.5.1, 2.2.5.2, 2.2.5.3, and 2.2.5.4). Interlink
 * identifies whether the entry contains a target in another DFS namespace, as
 * determined by the test in section 3.1.5.4.5. TargetFailback is used only for
 * DFS_REFERRAL_V4 and contains the value from the TargetFailback bit of the
 * referral header (as specified in section 2.2.4). TTL contains a value derived
 * from the TimeToLive field of a referral entry (as specified in sections
 * 2.2.5.1, 2.2.5.2, 2.2.5.3, and 2.2.5.4). This is the time stamp at which a
 * ReferralCache entry is considered to be expired. An implementation is free to
 * come up with soft and hard time-outs based on the TimeToLive field of the
 * referral entry, for example. The soft time-out can be used to initiate a
 * ReferralCache entry refresh operation while permitting the use of the
 * ReferralCache entry; the hard time-out limit can be used to fail any
 * operation using the ReferralCache entry if all attempts to refresh it
 * fail.<4> TargetHint identifies a target in TargetList that was last
 * successfully used by the DFS client. TargetList consists of tuples of the
 * form <TargetPath, TargetSetBoundary>, where TargetPath is the string pointed
 * to by the NetworkAddressOffset field (as specified in sections 2.2.5.2,
 * 2.2.5.3, and 2.2.5.4). TargetSetBoundary is only present in V4 referrals and
 * reflects the value from the TargetSetBoundary of the referral entry (as
 * specified in section 2.2.5.4).
 */
public class ReferralCache {

    Hashtable<String, ReferralCacheEntry> cache = new Hashtable<String, ReferralCacheEntry>();
    DFS dfs; // the owner

    public enum RootOrLink {
        RCE_LINK(0x0),
        RCE_ROOT(0x1);
        RootOrLink(int value) {
            this.value = value;
        }

        private int value;

        public int getValue() {
            return value;
        }

        public static RootOrLink get(int serverType) {
            if (serverType == RCE_LINK.value) {
                return RCE_LINK;
            } else if (serverType == RCE_ROOT.value) {
                return RCE_ROOT;
            }
            return null;
        }
    };

    public class ReferralCacheEntry {
        String dfsPathPrefix;
        RootOrLink rootOrLink;
        boolean interlink;
        int ttl;
        long expires;
        boolean targetFailback;
        TargetSetEntry targetHint;
        List<TargetSetEntry> targetList;

        public ReferralCacheEntry(SMB2GetDFSReferralResponse response) {
            for (int i = 0; i < response.referralEntries.size(); i++) {
                if (response.referralEntries.get(i).path == null) {
                    // illegal value for referral cache entry.
                    throw new IllegalStateException("Path cannot be null for a ReferralCacheEntry?");
                }
            }
            
            this.dfsPathPrefix = response.referralEntries.get(0).dfsPath;
            this.rootOrLink = RootOrLink.get(response.referralEntries.get(0).serverType);
            
// 3.1.5.4.5 Determining Whether a Referral Response is an Interlink
// A referral response is an Interlink if either of the following two conditions holds:
// - If the ReferralServers and StorageServers bits of the ReferralHeaderFlags field in the referral header 
//   (as specified in section 2.2.4) are set to 1 and 0 respectively.
// - If the TargetList has one entry, and a lookup of the first path component of the TargetList entry 
//   against the DomainCache results in a cache hit, indicating that the path refers to a domain namespace.
            
            this.interlink = isSet(response.referralHeaderFlags, ReferralHeaderFlags.ReferralServers)
                    && !isSet(response.referralHeaderFlags, ReferralHeaderFlags.StorageServers);
            if (!this.interlink && response.referralEntries.size() == 1) {
                String[] pathEntries = DFS.parsePath(response.referralEntries.get(0).path);
                this.interlink = (dfs.domainCache.lookup(pathEntries[0]) != null);
            }
            this.ttl = response.referralEntries.get(0).ttl;
            this.expires = System.currentTimeMillis() + this.ttl * 1000L;
            this.targetFailback = isSet(response.referralHeaderFlags, SMB2GetDFSReferralResponse.ReferralHeaderFlags.TargetFailback);
            targetList = new ArrayList<TargetSetEntry>(response.referralEntries.size());
            for (DFSReferral r : response.referralEntries) {
                TargetSetEntry e = new TargetSetEntry();
                e.targetPath = r.path;
                targetList.add(e);
            }
            this.targetHint = targetList.get(0);
        }

        boolean isExpired() {
            long now = System.currentTimeMillis();
            return (now < expires);
        }
        
        boolean isLink() {
            return rootOrLink == RootOrLink.RCE_LINK;
        }
        
        boolean isRoot() {
            return rootOrLink == RootOrLink.RCE_ROOT;
        }
        
        boolean isInterlink() {
            return rootOrLink == RootOrLink.RCE_LINK && interlink;
        }
        
        @Override
        public String toString() {
            return dfsPathPrefix+"->"+targetHint.targetPath+", "+targetList;
        }

    }

    public class TargetSetEntry {
        String targetPath;
        boolean targetSetBoundary;
    }

    ReferralCache(DFS dfs) {
        this.dfs = dfs;
    }
    public ReferralCacheEntry lookup(String path) {
        return cache.get(path);
    }

    public void put(ReferralCacheEntry referralCacheEntry) {
        cache.put(referralCacheEntry.dfsPathPrefix, referralCacheEntry);
    }
    
    public void clear() {
        cache.clear();
    }
}
