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

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;

/**
 * [MS-DFSC].pdf: 3.1.1 Abstract Data Model
 * <p>
 * ReferralCache: This cache contains root, link, and sysvol referral responses.
 * A hit on a ReferralCache entry indicates that the path in a name resolution
 * operation is a DFS Root, DFS link, or a SYSVOL/NETLOGON share. A
 * ReferralCache entry conceptually contains entries indexed by a DFS path
 * prefix, DFSPathPrefix. An entry is a tuple of the form {@code <DFSPathPrefix,
 * RootOrLink, Interlink, TTL, TargetFailback, TargetHint, TargetList>}.
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
 * fail.&lt;4&gt; TargetHint identifies a target in TargetList that was last
 * successfully used by the DFS client. TargetList consists of tuples of the
 * form {@code <TargetPath, TargetSetBoundary>}, where TargetPath is the string
 * pointed
 * to by the NetworkAddressOffset field (as specified in sections 2.2.5.2,
 * 2.2.5.3, and 2.2.5.4). TargetSetBoundary is only present in V4 referrals and
 * reflects the value from the TargetSetBoundary of the referral entry (as
 * specified in section 2.2.5.4).
 */
public class ReferralCache {

    private ReferralCacheNode cacheRoot = new ReferralCacheNode("<root>");

    public static class TargetSetEntry {
        final DFSPath targetPath;
        final boolean targetSetBoundary;

        public TargetSetEntry(String targetPath, boolean targetSetBoundary) {
            this.targetPath = new DFSPath(targetPath);
            this.targetSetBoundary = targetSetBoundary;
        }

        public DFSPath getTargetPath() {
            return targetPath;
        }

        @Override
        public String toString() {
            return "TargetSetEntry[" + targetPath + ",targetSetBoundary=" + targetSetBoundary + "]";
        }
    }

    public ReferralCacheEntry lookup(DFSPath dfsPath) {
        List<String> pathComponents = dfsPath.getPathComponents();
        ReferralCacheEntry referralEntry = cacheRoot.getReferralEntry(pathComponents.iterator());
        return referralEntry;
    }

    public void clear(DFSPath dfsPath) {
        List<String> pathComponents = dfsPath.getPathComponents();
        cacheRoot.deleteExpiredReferralEntry(pathComponents);
    }

    public void put(ReferralCacheEntry referralCacheEntry) {
        List<String> pathComponents = new DFSPath(referralCacheEntry.dfsPathPrefix).getPathComponents();
        cacheRoot.addReferralEntry(pathComponents.iterator(), referralCacheEntry);
    }

    public void clear() {
        cacheRoot.clear();
    }


    public static class ReferralCacheEntry {
        private final String dfsPathPrefix;
        private final DFSReferral.ServerType rootOrLink;
        private final boolean interlink;
        private final int ttl;
        private final long expires;
        private final boolean targetFailback;
        private int targetHint = 0;
        private final List<TargetSetEntry> targetList;

        public ReferralCacheEntry(SMB2GetDFSReferralResponse response, DomainCache domainCache) {
            List<DFSReferral> referralEntries = response.getReferralEntries();
            for (DFSReferral referralEntry : referralEntries) {
                if (referralEntry.getPath() == null) {
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

            boolean interlink = response.getReferralHeaderFlags().contains(ReferralHeaderFlags.ReferralServers)
                && !response.getReferralHeaderFlags().contains(ReferralHeaderFlags.StorageServers);
            if (!interlink && referralEntries.size() == 1) {
                List<String> pathEntries = new DFSPath(firstReferral.getPath()).getPathComponents();
                interlink = (domainCache.lookup(pathEntries.get(0)) != null);
            }

            this.interlink = interlink;
            this.ttl = firstReferral.getTtl();
            this.expires = System.currentTimeMillis() + this.ttl * 1000L;
            this.targetFailback = response.getReferralHeaderFlags().contains(ReferralHeaderFlags.TargetFailback);
            List<TargetSetEntry> targetList = new ArrayList<>(referralEntries.size());
            for (DFSReferral r : referralEntries) {
                TargetSetEntry e = new TargetSetEntry(r.getPath(), false);
                targetList.add(e);
            }
            this.targetList = Collections.unmodifiableList(targetList);
        }

        public boolean isExpired() {
            long now = System.currentTimeMillis();
            return (now > expires);
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
            return targetList.get(targetHint);
        }

        public synchronized TargetSetEntry nextTargetHint() {
            if (targetHint < targetList.size()-1) {
                targetHint++;
                return getTargetHint();
            } else {
                return null;
            }
        }

        public List<TargetSetEntry> getTargetList() {
            return targetList;
        }

        @Override
        public String toString() {
            return dfsPathPrefix + "->" + getTargetHint().targetPath  + "(" +  rootOrLink + "), " + targetList;
        }

    }

    private static class ReferralCacheNode {
        static final AtomicReferenceFieldUpdater<ReferralCacheNode, ReferralCacheEntry> ENTRY_UPDATER = AtomicReferenceFieldUpdater.newUpdater(ReferralCacheNode.class, ReferralCacheEntry.class, "entry");

        private final String pathComponent;
        private final Map<String, ReferralCacheNode> childNodes = new ConcurrentHashMap<>();
        private volatile ReferralCacheEntry entry;

        ReferralCacheNode(String pathComponent) {
            this.pathComponent = pathComponent;
        }

        void addReferralEntry(Iterator<String> pathComponents, ReferralCacheEntry entry) {
            if (pathComponents.hasNext()) {
                String component = pathComponents.next().toLowerCase();
                ReferralCacheNode referralCacheNode = childNodes.get(component);
                if (referralCacheNode == null) {
                    childNodes.put(component, (referralCacheNode = new ReferralCacheNode(component)));
                }
                referralCacheNode.addReferralEntry(pathComponents, entry);
            } else {
                ENTRY_UPDATER.set(this, entry);
            }
        }

        ReferralCacheEntry getReferralEntry(Iterator<String> pathComponents) {
            if (pathComponents.hasNext()) {
                String component = pathComponents.next().toLowerCase();
                ReferralCacheNode referralCacheNode = childNodes.get(component);
                if (referralCacheNode != null) {
                    return referralCacheNode.getReferralEntry(pathComponents);
                }
            }
            return ENTRY_UPDATER.get(this);
        }

        void deleteExpiredReferralEntry(List<String> pathComponents) {
            if (this.entry != null && this.entry.isExpired() &&
                !this.entry.isRoot()) {
                this.clear();
                return;
            }
            if (pathComponents!=null && !pathComponents.isEmpty()) {
                String component = pathComponents.get(0).toLowerCase();
                ReferralCacheNode referralCacheNode = childNodes.get(component);
                if (referralCacheNode != null) {
                    referralCacheNode.deleteExpiredReferralEntry(pathComponents.subList(1,pathComponents.size()));
                }
            }
        }

        void clear() {
            this.childNodes.clear();
            ENTRY_UPDATER.set(this, null);
        }
    }
}
