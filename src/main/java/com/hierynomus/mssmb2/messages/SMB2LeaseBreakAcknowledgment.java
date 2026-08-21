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
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.smb.SMBBuffer;

/**
 * Client → server SMB2 Lease Break Acknowledgment ([MS-SMB2] 2.2.24.2, StructureSize 36).
 * Sent in reply to a Lease Break Notification whose Flags had ACK_REQUIRED. {@code leaseState}
 * MUST be a subset of the notification's NewLeaseState.
 */
public class SMB2LeaseBreakAcknowledgment extends SMB2Packet {
    private final LeaseKey leaseKey;
    private final long leaseState;

    public SMB2LeaseBreakAcknowledgment(SMB2Dialect dialect, long sessionId, long treeId,
                                        LeaseKey leaseKey, long leaseState) {
        super(36, dialect, SMB2MessageCommandCode.SMB2_OPLOCK_BREAK, sessionId, treeId);
        this.leaseKey = leaseKey;
        this.leaseState = leaseState;
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(structureSize);          // StructureSize (36)
        buffer.putReserved2();                    // Reserved
        buffer.putReserved4();                    // Flags = 0
        buffer.putRawBytes(leaseKey.getBytes());  // LeaseKey (16)
        buffer.putUInt32(leaseState);             // LeaseState (subset of NewLeaseState)
        buffer.putReserved(8);                    // LeaseDuration = 0
    }
}
