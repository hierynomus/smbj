package com.hieronymus.mssmb2.dfs;

import com.hierynomus.smbj.common.SMBBuffer;

public class SMB2GetDFSReferralEx {
    int maxReferralLevel;
    int requestFlags;
    String requestFileName;
    String siteName;
    
    enum RequestFlags {
        FLAGS_SITENAMEPRESENT(0x1);
        
        private int value;

        RequestFlags(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }
    
    public SMB2GetDFSReferralEx(String path) {
        maxReferralLevel = 0;
        requestFlags = 0;
        requestFileName = path;
        siteName = null;
    }

    public SMB2GetDFSReferralEx(String path, String site) {
        maxReferralLevel = 0;
        requestFlags = RequestFlags.FLAGS_SITENAMEPRESENT.getValue();
        requestFileName = path;
        siteName = site;
    }
    
    public void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(maxReferralLevel);
        buffer.putUInt16(requestFlags);
        
        if ((requestFlags & RequestFlags.FLAGS_SITENAMEPRESENT.getValue()) != 0) { 
            buffer.putUInt32(requestFileName.length()+2+siteName.length()+2);
        } else {
            buffer.putUInt32(requestFileName.length()+2);
        }
        
        buffer.putStringLengthUInt16(requestFileName);
        buffer.putString(requestFileName);
        
        if ((requestFlags & RequestFlags.FLAGS_SITENAMEPRESENT.getValue()) != 0) { 
            buffer.putStringLengthUInt16(requestFileName);
            buffer.putString(requestFileName);
        }
    }

}
