package com.hieronymus.mssmb2.dfs;

import java.util.List;

public class ReferralCache {
//    ReferralCache: This cache contains root, link, and sysvol referral responses. A hit on a ReferralCache entry indicates that the path in a name resolution operation is a DFS Root, DFS link, or a SYSVOL/NETLOGON share.
//    A ReferralCache entry conceptually contains entries indexed by a DFS path prefix, DFSPathPrefix. An entry is a tuple of the form <DFSPathPrefix, RootOrLink, Interlink, TTL, TargetFailback, TargetHint, TargetList>.
//    DFSPathPrefix is the DFS path that corresponds to a DFS root or a DFS link, and is the same as the string pointed to by the DFSPathOffset of a DFS_REFERRAL_V2, DFS_REFERRAL_V3 or DFS_REFERRAL_V4 referral entry.
//    RootOrLink identifies whether the entry contains DFS root targets or DFS link targets. It reflects the value from the ServerType field of a referral entry (as specified in sections 2.2.5.1, 2.2.5.2, 2.2.5.3, and 2.2.5.4).
//    Interlink identifies whether the entry contains a target in another DFS namespace, as determined by the test in section 3.1.5.4.5.
//    TargetFailback is used only for DFS_REFERRAL_V4 and contains the value from the TargetFailback bit of the referral header (as specified in section 2.2.4).
//    TTL contains a value derived from the TimeToLive field of a referral entry (as specified in sections 2.2.5.1, 2.2.5.2, 2.2.5.3, and 2.2.5.4). This is the time stamp at which a ReferralCache entry is considered to be expired. An implementation is free to come up with soft and hard time-outs based on the TimeToLive field of the referral entry, for example. The soft time-out can be used to initiate a ReferralCache entry refresh operation while permitting the use of the ReferralCache entry; the hard time-out limit can be used to fail any operation using the ReferralCache entry if all attempts to refresh it fail.<4>
//    TargetHint identifies a target in TargetList that was last successfully used by the DFS client. TargetList consists of tuples of the form <TargetPath, TargetSetBoundary>, where TargetPath is the string pointed to by the NetworkAddressOffset field (as specified in sections 2.2.5.2, 2.2.5.3, and 2.2.5.4). TargetSetBoundary is only present in V4 referrals and reflects the value from the TargetSetBoundary of the referral entry (as specified in section 2.2.5.4).

    class ReferralCacheEntry {
        String DFSPathPrefix;
        int RootOrLink; // ServerType?
        boolean Interlink;
        int TTL; 
        boolean TargetFailback;
        TargetSetEntry TargetHint; 
        List<TargetSetEntry> TargetList;
    }
    class TargetSetEntry {
        String TargetPath;
        boolean TargetSetBoundary;
    }
}
