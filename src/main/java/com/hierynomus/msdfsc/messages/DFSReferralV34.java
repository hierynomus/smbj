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

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.isSet;

public class DFSReferralV34 extends DFSReferral {
    private static final int SIZE = 34;

    DFSReferralV34() {
    }


    // For testing only
    DFSReferralV34(int version, ServerType serverType, int referralEntryFlags, int ttl, String dfsPath, String dfsAlternatePath, String path) {
        super(version, serverType, referralEntryFlags);
        this.ttl = ttl;
        this.dfsPath = dfsPath;
        this.dfsAlternatePath = dfsAlternatePath;
        this.path = path;
    }

    DFSReferralV34(int version, ServerType serverType, int referralEntryFlags, int ttl, String specialName, List<String> expandedNames) {
        super(version, serverType, referralEntryFlags);
        this.ttl = ttl;
        this.specialName = specialName;
        this.expandedNames = expandedNames;
    }

    @Override
    protected void readReferral(SMBBuffer buffer, int referralStartPos) throws Buffer.BufferException {
        ttl = buffer.readUInt32AsInt(); // TimeToLive (4 bytes)
        if (!isSet(referralEntryFlags, ReferralEntryFlags.NameListReferral)) {
            dfsPath = readOffsettedString(buffer, referralStartPos, buffer.readUInt16()); // DFSPath(Offset) (2 bytes)
            dfsAlternatePath = readOffsettedString(buffer, referralStartPos, buffer.readUInt16()); // DFSAlternatePath(Offset) (2 bytes)
            path = readOffsettedString(buffer, referralStartPos, buffer.readUInt16()); // NetworkAddress(Offset) (2 bytes)
            buffer.skip(16); // ServiceSiteGuid (16 bytes) - ignored
        } else {
            specialName = readOffsettedString(buffer, referralStartPos, buffer.readUInt16()); // SpecialName(Offset) (2 bytes)
            int nrNames = buffer.readUInt16(); // NumberOfExpandedNames (2 bytes)
            int firstExpandedNameOffset = buffer.readUInt16(); // ExpendedNameOffset (2 bytes)
            expandedNames = new ArrayList<>(nrNames);
            int curPos = buffer.rpos();
            buffer.rpos(referralStartPos + firstExpandedNameOffset);
            for (int i = 0; i < nrNames; i++) {
                expandedNames.add(buffer.readNullTerminatedString(StandardCharsets.UTF_16));
            }
            buffer.rpos(curPos);
            // Padding will be skipped automatically
        }
    }

    @Override
    int writeReferral(SMBBuffer buffer, final int entryStartPos, final int bufferDataOffset) {
        int offset = bufferDataOffset;
        buffer.putUInt32(ttl); // TimeToLive (4 bytes)
        if (!isSet(referralEntryFlags, ReferralEntryFlags.NameListReferral)) {
            buffer.putUInt16(offset - entryStartPos); // DFSPathOffset (2 bytes)
            offset += (dfsPath.length() + 1) * 2;
            buffer.putUInt16(offset - entryStartPos); // DFSAlternatePathOffset (2 bytes)
            offset += (dfsAlternatePath.length() + 1) * 2;
            buffer.putUInt16(offset - entryStartPos); // NetworkAddressOffset (2 bytes)
            offset += (path.length() + 1) * 2;
            buffer.putReserved4();
            buffer.putReserved4();
            buffer.putReserved4();
            buffer.putReserved4(); // ServiceSiteGuid (16 bytes)
            return offset;
        } else {
            buffer.putUInt16(offset - entryStartPos); // SpecialNameOffset (2 bytes)
            offset += (specialName.length() + 1) * 2;
            buffer.putUInt16(expandedNames.size()); // NumberOfExpandedNames (2 bytes)
            buffer.putUInt16(offset - entryStartPos); // ExpandedNameOffset (2 bytes)
            for (String expandedName : expandedNames) {
                offset += (expandedName.length() + 1) * 2;
            }
            return offset;
        }
    }

    @Override
    void writeOffsettedData(SMBBuffer buffer) {
        if (!isSet(referralEntryFlags, ReferralEntryFlags.NameListReferral)) {
            buffer.putNullTerminatedString(dfsPath, StandardCharsets.UTF_16);
            buffer.putNullTerminatedString(dfsAlternatePath, StandardCharsets.UTF_16);
            buffer.putNullTerminatedString(path, StandardCharsets.UTF_16);
        } else {
            buffer.putNullTerminatedString(specialName, StandardCharsets.UTF_16);
            for (String expandedName : expandedNames) {
                buffer.putNullTerminatedString(expandedName, StandardCharsets.UTF_16);
            }
        }
    }

    @Override
    protected int determineSize() {
        return SIZE;
    }
}
