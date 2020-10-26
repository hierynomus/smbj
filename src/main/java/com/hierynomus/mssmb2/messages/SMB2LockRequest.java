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
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.messages.submodule.SMB2LockElement;
import com.hierynomus.smb.SMBBuffer;

import java.util.List;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toLong;

/**
 * [MS-SMB2].pdf 2.2.26 SMB2 LOCK Request
 *
 */
public class SMB2LockRequest extends SMB2Packet {

    private final short lockSequenceNumber;
    private final int lockSequenceIndex;
    private final SMB2FileId fileId;
    private final List<SMB2LockElement> lockElements;

    public SMB2LockRequest(SMB2Dialect dialect, long sessionId, long treeId,
                           short lockSequenceNumber, int lockSequenceIndex,
                           SMB2FileId fileId, List<SMB2LockElement> lockElements) {
        super(48, dialect, SMB2MessageCommandCode.SMB2_LOCK, sessionId, treeId);
        if(lockSequenceNumber < 0 || lockSequenceNumber > 15) {
            throw new IllegalArgumentException("Only 4-bit integer value is allowed for lockSequenceNumber.");
        }
        this.lockSequenceNumber = lockSequenceNumber;
        if(lockSequenceIndex < 0 || lockSequenceIndex > 64) {
            throw new IllegalArgumentException("Only value between 0 to 64 (inclusive) is allowed for lockSequenceIndex.");
        }
        this.lockSequenceIndex = lockSequenceIndex;
        this.fileId = fileId;
        this.lockElements = lockElements;
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(structureSize); // StructureSize (2 bytes)
        buffer.putUInt16(lockElements.size()); // LockCount (2 bytes)
        buffer.putUInt32(getLsnAndLsi());  // LockSequenceNumber (4 bits) and LockSequenceIndex (28 bits)
        fileId.write(buffer); // FileId (16 bytes)
        for (SMB2LockElement lockElement : lockElements) {
            buffer.putUInt64(lockElement.getOffset()); // Offset (8 bytes)
            buffer.putUInt64(lockElement.getLength()); // Length (8 bytes)
            buffer.putUInt32(toLong(lockElement.getLockFlags())); // Flags (4 bytes)
            buffer.putReserved4(); // Reserved (4 bytes)
        }

    }

    private int getLsnAndLsi() {
        return (this.lockSequenceIndex << 4) + this.lockSequenceNumber;
    }
}
