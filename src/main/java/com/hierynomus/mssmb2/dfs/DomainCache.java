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
package com.hierynomus.mssmb2.dfs;

import java.util.Hashtable;
import java.util.List;

// [MS-DFSC]:
// DomainCache: Applicable only for a computer joined to a domain. This cache contains a list of trusted domains in 
// both NetBIOS and fully qualified domain name forms, in addition to a list of DC host names for each domain. 
// Conceptually, this is an array of tuples of the form <DomainName, DCHint, DCList>. Cache lookup involves finding 
// a DomainCache entry with a matching DomainName. This can be used to check for a valid domain name or to find a DC 
// host name for a given domain name. DCHint identifies a DC host name from DCList that is the DC that was last 
// successfully used by the DFS client.
public class DomainCache {
    private Hashtable<String,DomainCacheEntry> cache = new Hashtable<String,DomainCacheEntry>(); //TODO reasonable initial size
    
    public class DomainCacheEntry {
        String domainName;
        String DCHint;
        List<String> DCList;
    }

    public DomainCacheEntry lookup(String domainName) {
        return cache.get(domainName);
    }
    public void put(DomainCacheEntry domainCacheEntry) {
        cache.put(domainCacheEntry.domainName, domainCacheEntry);
    }
}
