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

import com.hierynomus.msdfsc.messages.DFSReferral;
import com.hierynomus.msdfsc.messages.SMB2GetDFSReferralResponse;
import com.hierynomus.msdfsc.messages.SMB2GetDFSReferralResponse.ReferralHeaderFlags;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

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

    private ConcurrentHashMap<String, ReferralCacheEntry> cache = new ConcurrentHashMap<>();

    public static class TargetSetEntry {
        String targetPath;
        boolean targetSetBoundary;

        public String getTargetPath() {
            return targetPath;
        }
    }

    public ReferralCacheEntry lookup(DFSPath dfsPath) {
        return null; // TODO
    }

    public void put(ReferralCacheEntry referralCacheEntry) {
        cache.put(referralCacheEntry.dfsPathPrefix, referralCacheEntry);
    }

    public void clear() {
        cache.clear();
    }


    public static class ReferralCacheEntry {
        String dfsPathPrefix;
        DFSReferral.ServerType rootOrLink;
        boolean interlink;
        int ttl;
        long expires;
        boolean targetFailback;
        TargetSetEntry targetHint;
        List<TargetSetEntry> targetList;

        public ReferralCacheEntry(SMB2GetDFSReferralResponse response) {
            List<DFSReferral> referralEntries = response.getReferralEntries();
            for (int i = 0; i < referralEntries.size(); i++) {
                if (referralEntries.get(i).getPath() == null) {
                    // illegal value for referral cache entry.
                    throw new IllegalStateException("Path cannot be null for a ReferralCacheEntry?");
                }
            }

            DFSReferral firstReferral = referralEntries.get(0);
            this.dfsPathPrefix = firstReferral.getDfsPath();
            this.rootOrLink = firstReferral.getServerType();

// 3.1.5.4.5 Determining Whether a Referral Response is an Interlink
// A referral response is an Interlink if either of the following two conditions holds:
// - If the ReferralServers and StorageServers bits of the ReferralHeaderFlags field in the referral header
//   (as specified in section 2.2.4) are set to 1 and 0 respectively.
// - If the TargetList has one entry, and a lookup of the first path component of the TargetList entry
//   against the DomainCache results in a cache hit, indicating that the path refers to a domain namespace.

            this.interlink = response.getReferralHeaderFlags().contains(ReferralHeaderFlags.ReferralServers)
                && !response.getReferralHeaderFlags().contains(ReferralHeaderFlags.StorageServers);
            if (!this.interlink && referralEntries.size() == 1) {
//                String[] pathEntries = new DFSPath(firstReferral.getPath()).getPathComponents();
//                TODO this.interlink = (dfs.domainCache.lookup(pathEntries[0]) != null);
                this.interlink = true; // TODO Lookup in domain cache
            }
            this.ttl = firstReferral.getTtl();
            this.expires = System.currentTimeMillis() + this.ttl * 1000L;
            this.targetFailback = response.getReferralHeaderFlags().contains(ReferralHeaderFlags.TargetFailback);
            targetList = new ArrayList<>(referralEntries.size());
            for (DFSReferral r : referralEntries) {
                TargetSetEntry e = new TargetSetEntry();
                e.targetPath = r.getPath();
                targetList.add(e);
            }
            this.targetHint = targetList.get(0);
        }

        public boolean isExpired() {
            long now = System.currentTimeMillis();
            return (now < expires);
        }

        public boolean isLink() {
            return rootOrLink == DFSReferral.ServerType.LINK;
        }

        public boolean isRoot() {
            return rootOrLink == DFSReferral.ServerType.ROOT;
        }

        public boolean isInterlink() {
            return isLink() && interlink;
        }

        public String getDfsPathPrefix() {
            return dfsPathPrefix;
        }


        public TargetSetEntry getTargetHint() {
            return targetHint;
        }

        public List<TargetSetEntry> getTargetList() {
            return targetList;
        }

        @Override
        public String toString() {
            return dfsPathPrefix + "->" + targetHint.targetPath + ", " + targetList;
        }

    }

}
