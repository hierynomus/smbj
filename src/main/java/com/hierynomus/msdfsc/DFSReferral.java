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

import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.smbj.common.SMBBuffer;

public class DFSReferral {
    private static final int REFERRAL_V34_SIZE = 34;
    private static final int REFERRAL_V2_SIZE = 22;
    int versionNumber;
    int pathConsumed;
    int ttl;
    // The ServerType field MUST be set to 0x0001 if root targets are returned. In all other cases, the ServerType 
    // field MUST be set to 0x0000.
    int serverType;
    public static int SERVERTYPE_LINK = 0x0000;
    public static int SERVERTYPE_ROOT = 0x0001;
    int referralEntryFlags;
    String path;
    int proximity;
    String dfsPath;
    String dfsAlternatePath;
    String specialName;
    List<String> expandedNames;

    public DFSReferral()
    {
    }

    public DFSReferral(
        int versionNumber,
        int ttl,
        int serverType,
        int referralEntryFlags,
        String link,
        String path,
        int proximity,
        String dfsPath,
        String dfsAlternatePath,
        String specialName,
        List<String> expandedNames) {
        this.versionNumber = versionNumber;
        this.ttl = ttl;
        this.serverType = serverType;
        this.referralEntryFlags = referralEntryFlags;
        this.path = path;
        this.proximity = proximity;
        this.dfsPath = dfsPath;
        this.dfsAlternatePath = dfsAlternatePath;
        this.specialName = specialName;
        this.expandedNames = expandedNames;
    }

    @Override
    public String toString() {
        return "DFSReferral[pathConsumed=" + pathConsumed +
            ",path=" + path +
            ",dfsPath=" + dfsPath +
            ",dfsAlternatePath=" + dfsAlternatePath +
            ",specialName=" + specialName +
            ",ttl=" + ttl + "]";
    }

    public static DFSReferral read(SMBBuffer buffer) throws BufferException {
        DFSReferral dfsr = new DFSReferral();
        dfsr.readRef(buffer);
        return dfsr;
    }

    private void readRef(SMBBuffer buffer) throws BufferException {
        int size;
        int dfsPathOffset;
        int dfsAlternatePathOffset;
        int networkAddressOffset;
        int start;
        int specialNameOffset;
        int numberOfExpandedNames;
        int expandedNameOffset;
        int r;
        start = buffer.rpos();
        versionNumber = buffer.readUInt16();
        size = buffer.readUInt16();
        serverType = buffer.readUInt16();
        referralEntryFlags = buffer.readUInt16();

        switch (versionNumber) {
            case 1:
                path = buffer.readZString();
                break;
            case 2:
                proximity = buffer.readUInt32AsInt();
                ttl = buffer.readUInt32AsInt();
                dfsPathOffset = buffer.readUInt16();
                dfsAlternatePathOffset = buffer.readUInt16();
                networkAddressOffset = buffer.readUInt16();
                r = buffer.rpos();
                buffer.rpos(start + dfsPathOffset);
                dfsPath = buffer.readZString();
                buffer.rpos(start + dfsAlternatePathOffset);
                dfsAlternatePath = buffer.readZString();
                buffer.rpos(start + networkAddressOffset);
                path = buffer.readZString();
    
                buffer.rpos(r + size);
                break;
            case 3:
            case 4:
                ttl = buffer.readUInt32AsInt();
                if ((referralEntryFlags & 0x0002) == 0) {
                    dfsPathOffset = buffer.readUInt16();
                    dfsAlternatePathOffset = buffer.readUInt16();
                    networkAddressOffset = buffer.readUInt16();
                    buffer.readUInt16(); // skip GUID
                    r = buffer.rpos();
                    buffer.rpos(start + dfsPathOffset);
                    dfsPath = buffer.readZString();
                    buffer.rpos(start + dfsAlternatePathOffset);
                    dfsAlternatePath = buffer.readZString();
                    buffer.rpos(start + networkAddressOffset);
                    path = buffer.readZString();
                } else {
                    specialNameOffset = buffer.readUInt16();
                    numberOfExpandedNames = buffer.readUInt16();
                    expandedNameOffset = buffer.readUInt16();
                    r = buffer.rpos();
                    buffer.rpos(start + specialNameOffset);
                    specialName = buffer.readZString();
                    buffer.rpos(start + expandedNameOffset);
                    expandedNames = new ArrayList<String>(numberOfExpandedNames);
                    for (int i = 0; i < numberOfExpandedNames; i++) {
                        expandedNames.add(buffer.readZString());
                    }
                    buffer.rpos(r + size);
                }
                break;
            default:
                throw new IllegalStateException("Invalid referral version number");
        }
    }

    public void writeTo(SMBBuffer buffer) throws BufferException {
        int offset;
        buffer.putUInt16(versionNumber);
        int size;
        switch (versionNumber) {
            case 1:
                size = 8 + ((path.length() + 1) * 2);
                break;
            case 2:
                size = REFERRAL_V2_SIZE;
                break;
            case 3:
            case 4:
                size = REFERRAL_V34_SIZE;
                break;
            default:
                throw new IllegalStateException("Invalid versionNumber");
        }
        buffer.putUInt16(size); //size
        buffer.putUInt16(serverType);
        if (expandedNames != null && expandedNames.size() > 0) {
            referralEntryFlags = referralEntryFlags | 0x0002;
        }
        buffer.putUInt16(referralEntryFlags);

        switch (versionNumber) {
            case 1:
                buffer.putZString(path);
                break;
            case 2:
                buffer.putUInt32(proximity);
                buffer.putUInt32(ttl);
                offset = REFERRAL_V2_SIZE;
                buffer.putUInt16(offset + 6);
                buffer.putUInt16(offset + 6 + (dfsPath.length() + 1) * 2);
                buffer.putUInt16(offset + 6 + ((dfsPath.length() + 1) * 2) + ((dfsAlternatePath.length() + 1) * 2));
                buffer.putZString(dfsPath);
                buffer.putZString(dfsAlternatePath);
                buffer.putZString(path);
                break;
            case 3:
            case 4:
                buffer.putUInt32(ttl);
                if ((referralEntryFlags & 0x0002) == 0) {
                    offset = REFERRAL_V34_SIZE;
                    buffer.putUInt16(offset);   // DFSPathOffset
                    offset += ((dfsPath != null) ? ((dfsPath.length() + 1) * 2) : 0);
                    buffer.putUInt16(offset);   // DFSAlternatePathOffset
                    offset += ((dfsAlternatePath != null) ? ((dfsAlternatePath.length() + 1) * 2) : 0);
                    buffer.putUInt16(offset);   // NetwordAddressOffset
                    buffer.putReserved4(); // ServiceSiteGuid / padding
                    buffer.putReserved4();
                    buffer.putReserved4();
                    buffer.putReserved4();
                    if (dfsPath != null) {
                        buffer.putZString(dfsPath);
                    }
                    if (dfsAlternatePath != null) {
                        buffer.putZString(dfsAlternatePath);
                    }
                    if (path != null) {
                        buffer.putZString(path);
                    }
                } else {
                    offset = REFERRAL_V34_SIZE;
                    buffer.putUInt16(offset); // SpecialNameOffset
                    buffer.putUInt16(expandedNames.size()); // NumberOfExpandedNames
                    offset += (specialName.length() + 1) * 2;
                    buffer.putUInt16(offset); // ExpandedNameOffset
                    buffer.putReserved4(); // padding
                    buffer.putReserved4();
                    buffer.putReserved4();
                    buffer.putReserved4();
                    buffer.putZString(specialName);
                    for (int i = 0; i < expandedNames.size(); i++) {
                        buffer.putZString(expandedNames.get(i));
                    }
                }
                break;
            default:
                throw new IllegalStateException("Invalid versionNumber");
        }
    }
}
