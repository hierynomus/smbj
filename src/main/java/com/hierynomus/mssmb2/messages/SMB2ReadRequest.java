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
package com.hierynomus.mssmb2.messages;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.mssmb2.SMB2MultiCreditPacket;
import com.hierynomus.smb.SMBBuffer;

/**
 * [MS-SMB2].pdf 2.2.19 SMB2 READ Request
 */
public class SMB2ReadRequest extends SMB2MultiCreditPacket {

    private final long offset;
    private final SMB2FileId fileId;

    public SMB2ReadRequest(
        SMB2Dialect dialect, SMB2FileId fileId,
        long sessionId, long treeId, long offset, int maxPayloadSize) {
        super(49, dialect, SMB2MessageCommandCode.SMB2_READ, sessionId, treeId, maxPayloadSize);
        this.fileId = fileId;
        this.offset = offset;
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(structureSize); // StructureSize (2 bytes)
        buffer.putByte((byte) 0); // Padding (1 byte)
        buffer.putByte((byte) 0); // Flags (1 byte)
        buffer.putUInt32(SINGLE_CREDIT_PAYLOAD_SIZE * getCreditsAssigned()); // Length (4 bytes)
        buffer.putUInt64(offset); // Offset (8 bytes)
        fileId.write(buffer);  // FileId (16 bytes)
        buffer.putUInt32(1); // MinimumCount (4 bytes)
        buffer.putUInt32(0); // Channel (4 bytes)
        buffer.putUInt32(0); // RemainingBytes (4 bytes)
        buffer.putUInt16(0); // ReadChannelInfoOffset (2 bytes)
        buffer.putUInt16(0); // ReadChannelInfoLength (2 bytes)
        buffer.putByte((byte) 0); // Buffer (variable)
    }
}
