package com.hieronymus.mssmb2.dfs;

import java.util.ArrayList;

import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.smbj.common.SMBBuffer;

public class SMB2GetDFSReferralResponse {
    int pathConsumed;
    int numberOfReferrals;
    int referralHeaderFlags;
    ArrayList<DFSReferral> referralEntries;
    String stringBuffer;

    public void read(SMBBuffer buffer) throws BufferException {
        pathConsumed = buffer.readUInt16();
        numberOfReferrals = buffer.readUInt16();
        referralHeaderFlags = buffer.readUInt32AsInt();
        for (int i=0; i<numberOfReferrals; i++) {
            referralEntries.add(DFSReferral.read(buffer));
        }
    }

}
