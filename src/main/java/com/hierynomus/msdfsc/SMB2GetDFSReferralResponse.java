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

import java.util.ArrayList;
import java.util.List;

import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.smbj.common.SMBBuffer;

public class SMB2GetDFSReferralResponse {
    String originalPath;
    int pathConsumed;
    int numberOfReferrals;
    int referralHeaderFlags;
    List<DFSReferral> referralEntries = new ArrayList<DFSReferral>();
    String stringBuffer;
    
    public SMB2GetDFSReferralResponse(String originalPath) {
        this.originalPath = originalPath;
    }
    
    public SMB2GetDFSReferralResponse(String originalPath,
        int pathConsumed,
        int numberOfReferrals,
        int referralHeaderFlags,
        List<DFSReferral> referralEntries,
        String stringBuffer) 
    {
        this.originalPath = originalPath;
        this.pathConsumed = pathConsumed;
        this.numberOfReferrals = numberOfReferrals;
        this.referralHeaderFlags = referralHeaderFlags;
        this.referralEntries = referralEntries;
        this.stringBuffer = stringBuffer;
    }

    
    enum ReferralHeaderFlags implements EnumWithValue<ReferralHeaderFlags> {
        ReferralServers(0x1),
        StorageServers(0x2),
        TargetFailback(0x4);
        
        private long value;

        ReferralHeaderFlags(long value) {
            this.value = value;
        }

        public long getValue() {
            return value;
        }    
    }

    public void read(SMBBuffer buffer) throws BufferException {
        pathConsumed = buffer.readUInt16();
        numberOfReferrals = buffer.readUInt16();
        referralHeaderFlags = buffer.readUInt32AsInt();
        for (int i=0; i<numberOfReferrals; i++) {
            DFSReferral ref = DFSReferral.read(buffer);
            if (ref.dfsPath == null) {
                ref.dfsPath = originalPath;
            }
            referralEntries.add(ref);

        }
    }
    public void writeTo(SMBBuffer buffer) throws BufferException {
        buffer.putUInt16(pathConsumed);
        buffer.putUInt16(numberOfReferrals);
        buffer.putUInt32(referralHeaderFlags);
        for (int i=0; i<referralEntries.size(); i++) {
            referralEntries.get(i).writeTo(buffer);
        }
    }
    
//    public String toString() {
//        System.outString originalPath;
//        int pathConsumed;
//        int numberOfReferrals;
//        int referralHeaderFlags;
//        List<DFSReferral> referralEntries = new ArrayList<DFSReferral>();
//        String stringBuffer;
//        
//    }
}
