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
package com.hierynomus.mssmb2.messages.create;

import com.hierynomus.mssmb2.LeaseKey;
import com.hierynomus.mssmb2.SMB2LeaseFlags;
import com.hierynomus.smb.SMBBuffer;

/**
 * Builds the {@code RqLs} lease create-context request payload ([MS-SMB2] 2.2.13.2.8 V1 /
 * 2.2.13.2.10 V2). V1 (32B) is the SMB 2.1 file lease; V2 (52B) is the SMB 3.x file /
 * <b>directory</b> lease (adds ParentLeaseKey + Epoch). Only the bytes inside the
 * context {@code data} live here; the surrounding TLV is supplied by {@link SMB2CreateContext}.
 */
public class SMB2LeaseCreateContext {
    /** The "RqLs" 4CC in network (big-endian) order. */
    public static final byte[] NAME = {0x52, 0x71, 0x4C, 0x73};

    public enum Version {
        V1, V2
    }

    private final Version version;
    private final LeaseKey leaseKey;
    private final long leaseState;
    private final LeaseKey parentLeaseKey;
    private final long flags;

    private SMB2LeaseCreateContext(Version version, LeaseKey leaseKey, long leaseState, LeaseKey parentLeaseKey) {
        this.version = version;
        this.leaseKey = leaseKey;
        this.leaseState = leaseState;
        boolean parentSet = parentLeaseKey != null && !parentLeaseKey.isAllZero();
        this.parentLeaseKey = parentSet ? parentLeaseKey : null;
        this.flags = parentSet ? SMB2LeaseFlags.SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET.getValue() : 0L;
    }

    /** SMB 2.1 file lease (V1, 32 bytes). */
    public static SMB2LeaseCreateContext v1(LeaseKey leaseKey, long leaseState) {
        return new SMB2LeaseCreateContext(Version.V1, leaseKey, leaseState, null);
    }

    /** SMB 3.x file / directory lease (V2, 52 bytes). {@code parentLeaseKey} may be null. */
    public static SMB2LeaseCreateContext v2(LeaseKey leaseKey, long leaseState, LeaseKey parentLeaseKey) {
        return new SMB2LeaseCreateContext(Version.V2, leaseKey, leaseState, parentLeaseKey);
    }

    public Version getVersion() {
        return version;
    }

    public long getFlags() {
        return flags;
    }

    /** The inner data blob: 32 bytes (V1) or 52 bytes (V2). */
    public byte[] toBytes() {
        SMBBuffer b = new SMBBuffer();
        b.putRawBytes(leaseKey.getBytes());   // LeaseKey (16)
        b.putUInt32(leaseState);              // LeaseState (4)
        b.putUInt32(flags);                   // (Lease)Flags (4) — V1 always 0
        b.putReserved(8);                     // LeaseDuration (8) = 0
        if (version == Version.V2) {
            byte[] pk = parentLeaseKey != null ? parentLeaseKey.getBytes() : new byte[LeaseKey.SIZE];
            b.putRawBytes(pk);                // ParentLeaseKey (16)
            b.putUInt16(0);                   // Epoch (2) — ALWAYS 0 on request
            b.putReserved2();                 // Reserved (2)
        }
        return b.getCompactData();
    }

    /** Wrap into the generic create-context (name "RqLs", data = {@link #toBytes()}). */
    public SMB2CreateContext toCreateContext() {
        return new SMB2CreateContext(NAME, toBytes());
    }
}
