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
 * Server → client SMB2 Lease Break Response ([MS-SMB2] 2.2.25.2, StructureSize 36) — the
 * reply to our {@link SMB2LeaseBreakAcknowledgment}. Arrives with a normal MessageId.
 */
public class SMB2LeaseBreakResponse extends SMB2Packet {
    private LeaseKey leaseKey;
    private long leaseState;

    /** Parse from a received packet (used by tests; the converter route uses the normal read path). */
    public SMB2LeaseBreakResponse parse(SMB2PacketData packetData) throws Buffer.BufferException {
        read(packetData);
        return this;
    }

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        buffer.readUInt16(); // StructureSize (36)
        buffer.skip(2);      // Reserved
        buffer.skip(4);      // Flags
        leaseKey = new LeaseKey(buffer.readRawBytes(LeaseKey.SIZE));
        leaseState = buffer.readUInt32();
        buffer.skip(8);      // LeaseDuration
    }

    public LeaseKey getLeaseKey() {
        return leaseKey;
    }

    public long getLeaseState() {
        return leaseState;
    }
}
