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
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

/**
 * Server-pushed SMB2 Lease Break Notification ([MS-SMB2] 2.2.23.2, StructureSize 44).
 * Delivered unsolicited with {@code MessageId = 0xFFFFFFFFFFFFFFFF}, command SMB2_OPLOCK_BREAK.
 */
public class SMB2LeaseBreakNotification extends SMB2Packet {
    public static final long SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED = 0x01L;

    private int newEpoch;
    private long flags;
    private LeaseKey leaseKey;
    private long currentLeaseState;
    private long newLeaseState;

    public SMB2LeaseBreakNotification() {
    }

    /** Parse from a received (all-FF) break packet (the notification has no outstanding request). */
    public SMB2LeaseBreakNotification parse(SMB2PacketData packetData) throws Buffer.BufferException {
        read(packetData);
        return this;
    }

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        int structureSize = buffer.readUInt16(); // StructureSize (MUST be 44)
        if (structureSize != 44) {
            throw new IllegalStateException("Not a lease break notification, StructureSize=" + structureSize);
        }
        newEpoch = buffer.readUInt16();           // NewEpoch
        flags = buffer.readUInt32();              // Flags
        leaseKey = new LeaseKey(buffer.readRawBytes(LeaseKey.SIZE));
        currentLeaseState = buffer.readUInt32();  // CurrentLeaseState
        newLeaseState = buffer.readUInt32();      // NewLeaseState
        buffer.skip(12);                          // BreakReason + AccessMaskHint + ShareMaskHint
    }

    public boolean isAckRequired() {
        return (flags & SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED) != 0;
    }

    public int getNewEpoch() {
        return newEpoch;
    }

    public LeaseKey getLeaseKey() {
        return leaseKey;
    }

    public long getCurrentLeaseState() {
        return currentLeaseState;
    }

    public long getNewLeaseState() {
        return newLeaseState;
    }
}
