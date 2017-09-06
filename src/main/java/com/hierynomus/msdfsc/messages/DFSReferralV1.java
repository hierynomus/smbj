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

public class DFSReferralV1 extends DFSReferral {

    DFSReferralV1() {
    }

    // For testing only
    DFSReferralV1(int version, ServerType serverType, String path) {
        super(version, serverType, 0);
        this.path = path;
    }

    @Override
    public void readReferral(SMBBuffer buffer, int referralStartPos) throws Buffer.BufferException {
        referralEntryFlags = 0; // Must be set to 0 for V1
        path = buffer.readNullTerminatedString(StandardCharsets.UTF_16);
    }

    @Override
    int writeReferral(SMBBuffer buffer, int entryStartPos, int bufferDataOffset) {
        buffer.putNullTerminatedString(path, StandardCharsets.UTF_16);
        return bufferDataOffset;
    }

    @Override
    void writeOffsettedData(SMBBuffer buffer) {
        // No offsetted data for referral v1
    }

    @Override
    protected int determineSize() {
        return 8 + ((path.length() + 1) * 2);
    }
}
