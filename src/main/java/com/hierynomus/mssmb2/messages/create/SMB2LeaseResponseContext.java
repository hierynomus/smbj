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

import java.util.Arrays;

import com.hierynomus.mssmb2.LeaseKey;
import com.hierynomus.mssmb2.SMB2LeaseState;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

/**
 * Parses the {@code RqLs} lease create-context <b>response</b> payload. V1 (32B) vs V2 (52B)
 * is disambiguated <b>solely by the data length</b> (V1 and V2 share the identical "RqLs"
 * 4CC). Exposes the server-granted lease state, key, and (V2) parent key + epoch.
 */
public class SMB2LeaseResponseContext {
    private final boolean v2;
    private final LeaseKey leaseKey;
    private final long leaseState;
    private final long flags;
    private final LeaseKey parentLeaseKey;
    private final int epoch;

    private SMB2LeaseResponseContext(boolean v2, LeaseKey leaseKey, long leaseState, long flags,
                                     LeaseKey parentLeaseKey, int epoch) {
        this.v2 = v2;
        this.leaseKey = leaseKey;
        this.leaseState = leaseState;
        this.flags = flags;
        this.parentLeaseKey = parentLeaseKey;
        this.epoch = epoch;
    }

    /** Parse the inner data blob; V1/V2 chosen strictly by {@code data.length} (32 vs 52). */
    public static SMB2LeaseResponseContext read(byte[] data) throws Buffer.BufferException {
        boolean v2;
        switch (data.length) {
            case 32:
                v2 = false;
                break;
            case 52:
                v2 = true;
                break;
            default:
                throw new IllegalArgumentException("Malformed RqLs response: DataLength=" + data.length);
        }
        SMBBuffer b = new SMBBuffer(data);
        LeaseKey key = new LeaseKey(b.readRawBytes(LeaseKey.SIZE));
        long state = b.readUInt32();
        long flags = b.readUInt32();
        b.skip(8); // LeaseDuration
        if (v2) {
            LeaseKey parent = new LeaseKey(b.readRawBytes(LeaseKey.SIZE));
            int epoch = b.readUInt16();
            b.skip(2); // Reserved
            return new SMB2LeaseResponseContext(true, key, state, flags, parent, epoch);
        }
        return new SMB2LeaseResponseContext(false, key, state, flags, null, 0);
    }

    /** Convenience over an already-located "RqLs" create context (spec-01 readAll). */
    public static SMB2LeaseResponseContext from(SMB2CreateContext ctx) throws Buffer.BufferException {
        if (!Arrays.equals(ctx.getName(), SMB2LeaseCreateContext.NAME)) {
            throw new IllegalArgumentException("Not an RqLs create context");
        }
        return read(ctx.getData());
    }

    public boolean isV2() {
        return v2;
    }

    public LeaseKey getLeaseKey() {
        return leaseKey;
    }

    public long getLeaseState() {
        return leaseState;
    }

    public long getFlags() {
        return flags;
    }

    public boolean isReadHandleGranted() {
        return SMB2LeaseState.isReadHandle(leaseState);
    }

    /** The parent lease key (V2 only), else {@code null}. */
    public LeaseKey getParentLeaseKey() {
        return parentLeaseKey;
    }

    /** The server lease epoch (V2 only), else 0. */
    public int getEpoch() {
        return epoch;
    }
}
