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

import com.hierynomus.mssmb2.LeaseKey;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2OplockLevel;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smb.SMBBuffer;

/**
 * Unified response for SMB2_OPLOCK_BREAK ([MS-SMB2] 2.2.25). Discriminates between
 * a traditional file-oplock break response (StructureSize 24, §2.2.25.1) and a lease
 * break response (StructureSize 36, §2.2.25.2) by reading StructureSize first.
 */
public class SMB2OplockBreakResponse extends SMB2Packet {

    private static final int STRUCTURE_SIZE_FILE_OPLOCK = 24;
    private static final int STRUCTURE_SIZE_LEASE       = 36;

    private boolean lease;

    // File-oplock fields (StructureSize 24)
    private SMB2OplockLevel oplockLevel;
    private SMB2FileId fileId;

    // Lease-break fields (StructureSize 36)
    private LeaseKey leaseKey;
    private long leaseState;

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        int structureSize = buffer.readUInt16();
        switch (structureSize) {
            case STRUCTURE_SIZE_FILE_OPLOCK:
                lease = false;
                oplockLevel = EnumWithValue.EnumUtils.valueOf(
                        buffer.readByte() & 0xFF, SMB2OplockLevel.class,
                        SMB2OplockLevel.SMB2_OPLOCK_LEVEL_NONE); // OplockLevel (1 byte)
                buffer.skip(1);  // Reserved (1 byte)
                buffer.skip(4);  // Reserved (4 bytes)
                fileId = SMB2FileId.read(buffer); // FileId (16 bytes)
                break;
            case STRUCTURE_SIZE_LEASE:
                lease = true;
                buffer.skip(2);  // Reserved (2 bytes)
                buffer.skip(4);  // Flags (4 bytes)
                leaseKey = new LeaseKey(buffer.readRawBytes(LeaseKey.SIZE)); // LeaseKey (16 bytes)
                leaseState = buffer.readUInt32(); // LeaseState (4 bytes)
                buffer.skip(8);  // LeaseDuration (8 bytes)
                break;
            default:
                throw new SMBRuntimeException(
                        "Unexpected SMB2_OPLOCK_BREAK response StructureSize: " + structureSize
                        + " (expected 24 for file oplock or 36 for lease break)");
        }
    }

    /** Returns {@code true} if this is a lease break response (StructureSize 36). */
    public boolean isLease() {
        return lease;
    }

    /** The oplock level; only meaningful when {@link #isLease()} is {@code false}. */
    public SMB2OplockLevel getOplockLevel() {
        return oplockLevel;
    }

    /** The file id; only meaningful when {@link #isLease()} is {@code false}. */
    public SMB2FileId getFileId() {
        return fileId;
    }

    /** The lease key; only meaningful when {@link #isLease()} is {@code true}. */
    public LeaseKey getLeaseKey() {
        return leaseKey;
    }

    /** The lease state; only meaningful when {@link #isLease()} is {@code true}. */
    public long getLeaseState() {
        return leaseState;
    }
}
