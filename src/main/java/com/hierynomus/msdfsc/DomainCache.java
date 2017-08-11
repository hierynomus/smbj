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
import com.hierynomus.protocol.commons.EnumWithValue;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * [MS-DFSC].pdf 3.1.1 Abstract Data Model DomainCache: Applicable only for a
 * computer joined to a domain. This cache contains a list of trusted domains in
 * both NetBIOS and fully qualified domain name forms, in addition to a list of
 * DC host names for each domain. Conceptually, this is an array of tuples of
 * the form <DomainName, DCHint, DCList>. Cache lookup involves finding a
 * DomainCache entry with a matching DomainName. This can be used to check for a
 * valid domain name or to find a DC host name for a given domain name. DCHint
 * identifies a DC host name from DCList that is the DC that was last
 * successfully used by the DFS client.
 */
public class DomainCache {
    private Map<String, DomainCacheEntry> cache = new ConcurrentHashMap<>();

    public static class DomainCacheEntry {
        String domainName;
        String DCHint;
        List<String> DCList;

        /**
         * 3.1.5.4.2 Receiving a DC Referral Response
         * This is applicable only to a domain-joined computer. The DFS client receives this referral response for the DC referral request that it
         * sent in step 5.2 of section 3.1.4.1. The DC referral response MUST be version 3 or later; otherwise, the client MUST ignore the referral response.
         * The client MUST verify that the NumberOfReferrals field of the referral header is 1 and that the NameListReferral bit is set in the referral entry.
         * The other bits of ReferralEntryFlags in the referral entry MUST be ignored. The NumberOfExpandedNames in the referral entry contains the number
         * of DC names returned. The client MUST use the value in the NumberOfExpandedNames field to determine how many names are present in the list at
         * ExpandedNameOffset. The client can access the first null-terminated Unicode DC name string that is returned by adding the value in the
         * ExpandedNameOffset field to the address of the referral entry. Immediately following the null termination of a DC name is the next DC name returned.
         * The client can access the null-terminated Unicode domain name that corresponds to the referral response by adding the value in the SpecialNameOffset
         * to the address of the referral entry.
         * The client MUST add the list of DCs determined for a domain name to DCList of the DomainCache entry that corresponds to the domain name.
         * If the DomainCache entry's DCList is not empty, the client MUST replace it with the DC list from the referral response and set DCHint to the
         * first DC in the new DCList.
         */
        public DomainCacheEntry(SMB2GetDFSReferralResponse response) {
            if (response.getReferralEntries().size() != 1) {
                throw new IllegalStateException("Expecting exactly 1 referral for a domain referral, found: " + response.getReferralEntries().size());
            }
            DFSReferral dfsReferral = response.getReferralEntries().get(0);
            if (!EnumWithValue.EnumUtils.isSet(dfsReferral.getReferralEntryFlags(), DFSReferral.ReferralEntryFlags.NameListReferral)) {
                throw new IllegalStateException("Referral Entry for '" + dfsReferral.getSpecialName() + "' does not have NameListReferral bit set.");
            }

            domainName = dfsReferral.getSpecialName();
            DCHint = dfsReferral.getExpandedNames().get(0);
            DCList = dfsReferral.getExpandedNames();
        }

        public String getDomainName() {
            return domainName;
        }

        public String getDCHint() {
            return DCHint;
        }

        public List<String> getDCList() {
            return DCList;
        }

        public String toString() {
            return domainName + "->" + DCHint + ", " + DCList;
        }
    }

    public DomainCacheEntry lookup(String domainName) {
        return cache.get(domainName);
    }

    public void put(DomainCacheEntry domainCacheEntry) {
        cache.put(domainCacheEntry.domainName, domainCacheEntry);
    }
}
