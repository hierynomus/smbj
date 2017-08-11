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

import java.nio.charset.StandardCharsets;
import java.util.List;

public abstract class DFSReferral {

    public enum ServerType implements EnumWithValue<ServerType> {
        LINK(0x0),
        ROOT(0x1);

        private long value;

        ServerType(long value) {
            this.value = value;
        }

        @Override
        public long getValue() {
            return value;
        }

    }
    public enum ReferralEntryFlags implements EnumWithValue<ReferralEntryFlags> {
        NameListReferral(0x02),
        TargetSetBoundary(0x04);

        private long value;

        ReferralEntryFlags(long v) {
            this.value = v;
        }

        @Override
        public long getValue() {
            return value;
        }

    }

    private int versionNumber;
    int ttl;
    // The ServerType field MUST be set to 0x0001 if root targets are returned. In all other cases, the ServerType
    // field MUST be set to 0x0000.
    private ServerType serverType;
    long referralEntryFlags;
    protected String path;
    String dfsPath;
    String dfsAlternatePath;
    String specialName;
    List<String> expandedNames;

    DFSReferral() {
    }

    // For testing only
    DFSReferral(int version, ServerType serverType, int referralEntryFlags) {
        this.versionNumber = version;
        this.serverType = serverType;
        this.referralEntryFlags = referralEntryFlags;
    }

    @Override
    public String toString() {
        return "DFSReferral[path=" + path +
            ",dfsPath=" + dfsPath +
            ",dfsAlternatePath=" + dfsAlternatePath +
            ",specialName=" + specialName +
            ",ttl=" + ttl + "]";
    }

    protected abstract void readReferral(SMBBuffer buffer, int referralStartPos) throws BufferException;

    static DFSReferral factory(SMBBuffer buffer) throws BufferException {
        int versionNumber = buffer.readUInt16();
        buffer.rpos(buffer.rpos() - 2); // Reset to version number.
        switch (versionNumber) {
            case 1:
                return new DFSReferralV1().read(buffer);
            case 2:
                return new DFSReferralV2().read(buffer);
            case 3:
            case 4:
                return new DFSReferralV34().read(buffer);
            default:
                throw new IllegalArgumentException("Incorrect version number " + versionNumber + " while parsing DFS Referrals");
        }
    }

    String readOffsettedString(SMBBuffer buffer, int referralStart, int offset) throws BufferException {
        int curr = buffer.rpos();
        buffer.rpos(referralStart + offset);
        String s = buffer.readNullTerminatedString(StandardCharsets.UTF_16);
        buffer.rpos(curr);
        return s;
    }

    final DFSReferral read(SMBBuffer buffer) throws BufferException {
        int start = buffer.rpos();
        versionNumber = buffer.readUInt16(); // VersionNumber (2 bytes)
        int size = buffer.readUInt16(); // Size (2 bytes)
        serverType = EnumWithValue.EnumUtils.valueOf(buffer.readUInt16(), ServerType.class, null); // ServerType (2 bytes)
        referralEntryFlags = buffer.readUInt16();
        readReferral(buffer, start);
        buffer.rpos(start + size);
        return this;
    }

    final int writeTo(SMBBuffer buffer, int bufferDataOffset) {
        int startPos = buffer.wpos();
        buffer.putUInt16(versionNumber);
        buffer.putUInt16(determineSize());
        buffer.putUInt16((int) serverType.value);
        buffer.putUInt16((int) referralEntryFlags);
        return writeReferral(buffer, startPos, bufferDataOffset);
    }

    abstract int writeReferral(SMBBuffer buffer, int entryStartPos, int bufferDataOffset);

    abstract void writeOffsettedData(SMBBuffer buffer);

    protected abstract int determineSize();

    public int getVersionNumber() {
        return versionNumber;
    }

    public int getTtl() {
        return ttl;
    }

    public ServerType getServerType() {
        return serverType;
    }

    public long getReferralEntryFlags() {
        return referralEntryFlags;
    }

    public String getPath() {
        return path;
    }

    public String getDfsPath() {
        return dfsPath;
    }

    public String getDfsAlternatePath() {
        return dfsAlternatePath;
    }

    public String getSpecialName() {
        return specialName;
    }

    public List<String> getExpandedNames() {
        return expandedNames;
    }

    public void setDfsPath(String dfsPath) {
        this.dfsPath = dfsPath;
    }
}
