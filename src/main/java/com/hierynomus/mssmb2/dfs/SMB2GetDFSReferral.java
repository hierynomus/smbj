package com.hieronymus.mssmb2.dfs;

import com.hierynomus.smbj.common.SMBBuffer;

public class SMB2GetDFSReferral {
    
    int maxReferralLevel = 1; //TODO shall we support version 1,2,3,4?
    String requestFileName;
    
    public SMB2GetDFSReferral(String path) {
        requestFileName = path;
    }
    
    public void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(maxReferralLevel);
        buffer.putZString(requestFileName);
    }
}
