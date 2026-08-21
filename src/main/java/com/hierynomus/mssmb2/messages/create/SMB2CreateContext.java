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

import java.util.ArrayList;
import java.util.List;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

/**
 * Generic, lease-agnostic SMB2_CREATE_CONTEXT TLV container ([MS-SMB2] 2.2.13.2).
 * <p>
 * This is the connective tissue every create context (lease, durable handle,
 * query-on-disk-id, ...) rides on. It treats {@code name} and {@code data} as
 * opaque byte arrays; higher layers (e.g. the {@code RqLs} lease context) encode
 * their typed payload into {@code data}.
 */
public class SMB2CreateContext {
    private static final int HEADER_SIZE = 16;

    private final byte[] name;
    private final byte[] data;

    public SMB2CreateContext(byte[] name, byte[] data) {
        this.name = name;
        this.data = data == null ? new byte[0] : data;
    }

    public byte[] getName() {
        return name;
    }

    public byte[] getData() {
        return data;
    }

    private static int align8(int n) {
        return (n + 7) & ~7;
    }

    /**
     * Serializes a chained list of create contexts at the buffer's current write position.
     * Handles the 16-byte header, 8-byte name/data alignment, inter-context 8-byte
     * alignment and {@code Next}-offset backfill ({@code Next = 0} on the last context,
     * with no trailing pad).
     *
     * @return the total number of bytes written (0 for a null/empty list).
     */
    public static int writeAll(SMBBuffer buffer, List<SMB2CreateContext> contexts) {
        if (contexts == null || contexts.isEmpty()) {
            return 0;
        }
        int start = buffer.wpos();
        for (int i = 0; i < contexts.size(); i++) {
            SMB2CreateContext ctx = contexts.get(i);
            boolean isLast = i == contexts.size() - 1;
            int ctxStart = buffer.wpos();
            int nameLen = ctx.name.length;
            int dataLen = ctx.data.length;
            int nameOffset = HEADER_SIZE; // header is 16 bytes, already 8-aligned
            int dataOffset = dataLen == 0 ? 0 : align8(nameOffset + nameLen);

            int nextPos = buffer.wpos();
            buffer.putUInt32(0);             // Next (placeholder, backfilled below)
            buffer.putUInt16(nameOffset);    // NameOffset
            buffer.putUInt16(nameLen);       // NameLength
            buffer.putReserved(2);           // Reserved
            buffer.putUInt16(dataOffset);    // DataOffset (0 when no data)
            buffer.putUInt32(dataLen);       // DataLength

            buffer.putRawBytes(ctx.name);    // name at offset 16
            if (dataLen > 0) {
                buffer.putReserved(dataOffset - (nameOffset + nameLen)); // align data to 8
                buffer.putRawBytes(ctx.data);
            }

            if (!isLast) {
                int ctxBytes = buffer.wpos() - ctxStart;
                int pad = align8(ctxBytes) - ctxBytes;
                buffer.putReserved(pad);
                int next = ctxBytes + pad;
                int save = buffer.wpos();
                buffer.wpos(nextPos);
                buffer.putUInt32(next);      // backfill Next to span inter-context pad
                buffer.wpos(save);
            }
            // last context: Next stays 0, no trailing pad
        }
        return buffer.wpos() - start;
    }

    /**
     * Parses a chained list of create contexts starting at absolute buffer position
     * {@code offset}, bounded by {@code length} bytes. The {@code Next} chain is
     * authoritative ({@code Next == 0} terminates); contexts are returned in encounter
     * order. Seeks by the per-context {@code NameOffset}/{@code DataOffset} so any
     * server ordering/padding is tolerated.
     */
    public static List<SMB2CreateContext> readAll(SMBBuffer buffer, int offset, int length) throws Buffer.BufferException {
        List<SMB2CreateContext> result = new ArrayList<>();
        if (length == 0) {
            return result;
        }
        buffer.rpos(offset);
        while (true) {
            int ctxStart = buffer.rpos();
            int next = (int) buffer.readUInt32();   // Next
            int nameOffset = buffer.readUInt16();   // NameOffset
            int nameLen = buffer.readUInt16();      // NameLength
            buffer.skip(2);                         // Reserved
            int dataOffset = buffer.readUInt16();   // DataOffset
            int dataLen = (int) buffer.readUInt32();// DataLength

            buffer.rpos(ctxStart + nameOffset);
            byte[] name = buffer.readRawBytes(nameLen);
            byte[] data;
            if (dataLen > 0 && dataOffset != 0) {
                buffer.rpos(ctxStart + dataOffset);
                data = buffer.readRawBytes(dataLen);
            } else {
                data = new byte[0];
            }
            result.add(new SMB2CreateContext(name, data));

            if (next == 0) {
                break;
            }
            buffer.rpos(ctxStart + next);
        }
        return result;
    }
}
