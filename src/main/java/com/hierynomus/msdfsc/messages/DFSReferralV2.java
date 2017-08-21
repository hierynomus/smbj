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

public class DFSReferralV2 extends DFSReferral {
    private static final int SIZE = 22;

    DFSReferralV2() {
    }

    // For testing only
    DFSReferralV2(int version, ServerType serverType, int ttl, String dfsPath, String dfsAlternatePath, String path) {
        super(version, serverType, 0);
        this.ttl = ttl;
        this.dfsPath = dfsPath;
        this.dfsAlternatePath = dfsAlternatePath;
        this.path = path;
    }

    @Override
    protected void readReferral(SMBBuffer buffer, int referralStartPos) throws Buffer.BufferException {
        referralEntryFlags = 0; // Must be set to 0 for V2
        buffer.readUInt32AsInt(); // Proximity (4 bytes) should be ignored
        ttl = buffer.readUInt32AsInt(); // TimeToLive (4 bytes)
        int dfsPathOffset = buffer.readUInt16(); // DFSPathOffset (2 bytes)
        int dfsAlternatePathOffset = buffer.readUInt16(); // DFSAlternatePathOffset (2 bytes)
        int networkAddressOffset = buffer.readUInt16(); // NetworkAddressOffset (2 bytes)

        dfsPath = readOffsettedString(buffer, referralStartPos, dfsPathOffset);
        dfsAlternatePath = readOffsettedString(buffer, referralStartPos, dfsAlternatePathOffset);
        path = readOffsettedString(buffer, referralStartPos, networkAddressOffset);
    }

    @Override
    int writeReferral(SMBBuffer buffer, final int entryStartPos, final int bufferDataOffset) {
        int offset = bufferDataOffset;
        buffer.putUInt32(0); // Proximity (4 bytes)
        buffer.putUInt32(ttl); // TimeToLive (4 bytes)
        buffer.putUInt16(offset - entryStartPos); // DFSPathOffset (2 bytes)
        offset += (dfsPath.length() + 1) * 2;
        buffer.putUInt16(offset - entryStartPos); // DFSAlternatePathOffset (2 bytes)
        offset += (dfsAlternatePath.length() + 1) * 2;
        buffer.putUInt16(offset - entryStartPos); // NetworkAddressOffset (2 bytes)
        offset += (path.length() + 1) * 2;
        return offset;
    }

    @Override
    void writeOffsettedData(SMBBuffer buffer) {
        buffer.putNullTerminatedString(dfsPath, StandardCharsets.UTF_16);
        buffer.putNullTerminatedString(dfsAlternatePath, StandardCharsets.UTF_16);
        buffer.putNullTerminatedString(path, StandardCharsets.UTF_16);
    }

    @Override
    protected int determineSize() {
        return SIZE;
    }
}
