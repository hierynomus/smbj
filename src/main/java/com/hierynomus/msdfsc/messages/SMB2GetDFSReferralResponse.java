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
package com.hierynomus.msdfsc.messages;

import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.smb.SMBBuffer;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

public class SMB2GetDFSReferralResponse {
    private String originalPath;
    private int pathConsumed;
    private EnumSet<ReferralHeaderFlags> referralHeaderFlags;
    private List<DFSReferral> referralEntries = new ArrayList<>();

    public SMB2GetDFSReferralResponse(String originalPath) {
        this.originalPath = originalPath;
    }

    // For testing only
    SMB2GetDFSReferralResponse(String originalPath, int pathConsumed, EnumSet<ReferralHeaderFlags> referralHeaderFlags, List<DFSReferral> referralEntries) {
        this.originalPath = originalPath;
        this.pathConsumed = pathConsumed;
        this.referralHeaderFlags = referralHeaderFlags;
        this.referralEntries = referralEntries;
    }

    public EnumSet<ReferralHeaderFlags> getReferralHeaderFlags() {
        return referralHeaderFlags;
    }

    public enum ReferralHeaderFlags implements EnumWithValue<ReferralHeaderFlags> {
        ReferralServers(0x1L),
        StorageServers(0x2L),
        TargetFailback(0x4L);

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
        int numberOfReferrals = buffer.readUInt16();
        referralHeaderFlags = EnumWithValue.EnumUtils.toEnumSet(buffer.readUInt32AsInt(), ReferralHeaderFlags.class);
        for (int i = 0; i < numberOfReferrals; i++) {
            DFSReferral ref = DFSReferral.factory(buffer);
            if (ref.getDfsPath() == null) {
                ref.setDfsPath(originalPath);
            }
            referralEntries.add(ref);
        }
    }

    public void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(pathConsumed);
        buffer.putUInt16(referralEntries.size());
        buffer.putUInt32(EnumWithValue.EnumUtils.toLong(referralHeaderFlags));
        int entriesEndIndex = buffer.wpos();
        for (DFSReferral referralEntry : referralEntries) {
            entriesEndIndex += referralEntry.determineSize();
        }
        int entryDataOffset = 0;
        for (DFSReferral referralEntry : referralEntries) {
            entryDataOffset = referralEntry.writeTo(buffer, entriesEndIndex + entryDataOffset);
        }
        for (DFSReferral referralEntry : referralEntries) {
            referralEntry.writeOffsettedData(buffer);
        }
    }

    public List<DFSReferral> getReferralEntries() {
        return referralEntries;
    }

    /**
     * 3.1.5.4. If the NumberOfReferrals field is at least 1, the client MUST determine the
     * version number of the referral response by accessing the VersionNumber field of the first
     * referral entry immediately following the referral header
     * @return the version number of the referral response.
     */
    public int getVersionNumber() {
        if (!referralEntries.isEmpty()) {
            return referralEntries.get(0).getVersionNumber();
        }
        return 0;
    }
}
