package com.hierynomus.mssmb2.dfs;

import java.util.List;

// DomainCache: Applicable only for a computer joined to a domain. This cache contains a list of trusted domains in 
// both NetBIOS and fully qualified domain name forms, in addition to a list of DC host names for each domain. 
// Conceptually, this is an array of tuples of the form <DomainName, DCHint, DCList>. Cache lookup involves finding 
// a DomainCache entry with a matching DomainName. This can be used to check for a valid domain name or to find a DC 
// host name for a given domain name. DCHint identifies a DC host name from DCList that is the DC that was last 
// successfully used by the DFS client.
public class DomainCache {
    public class DomainCacheEntry {
        String DomainName;
        String DCHint;
        List<String> DCList;
    }

    public DomainCacheEntry lookup(String domainName) {
        return null;//TODO implement me
    }
}
