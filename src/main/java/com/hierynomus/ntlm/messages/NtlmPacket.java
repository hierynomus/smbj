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
package com.hierynomus.ntlm.messages;

import com.hierynomus.protocol.Packet;
import com.hierynomus.protocol.commons.buffer.Buffer;

public class NtlmPacket implements Packet<NtlmPacket, Buffer.PlainBuffer> {

    @Override
    public void write(Buffer.PlainBuffer buffer) {
        throw new UnsupportedOperationException("Not implemented by base class");
    }

    @Override
    public NtlmPacket read(Buffer.PlainBuffer buffer) throws Buffer.BufferException {
        throw new UnsupportedOperationException("Not implemented by base class");
    }

    protected void writeFields(Buffer.PlainBuffer buffer, int offset, byte[][] bufs, Object[] others) {
        int numFields = bufs.length;
        for (int i = 0; i < bufs.length; ++i) {
            assert (bufs[i] != null);
            buffer.putUInt16(bufs[i].length); // Offset
            buffer.putUInt16(bufs[i].length); // Length
            offset = offset + ((i == 0) ? 0 : bufs[i - 1].length);
            buffer.putUInt32(offset);
        }
        if (others != null) {
            for (int i = 0; i < others.length; ++i) {
                if (others[i] instanceof Integer) {
                    buffer.putUInt16((Integer)others[i]);
                } else if (others[i] instanceof Long) {
                    buffer.putUInt32((Long)others[i]);
                } else {
                    throw new RuntimeException("Unsupported object type " + others[i]);
                }
            }
        }
        for (int i = 0; i < bufs.length; ++i) {
            if (bufs[i].length > 0) {
                buffer.putRawBytes(bufs[i]);
            }
        }
    }
}
