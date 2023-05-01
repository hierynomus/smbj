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
package com.hierynomus.ntlm.av;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;

public class AvPairChannelBindings extends AvPair<byte[]> {

    AvPairChannelBindings() {
        super(AvId.MsvAvChannelBindings);
    }

    @Override
    public void write(Buffer<?> buffer) {
        buffer.putUInt16((int) this.avId.getValue()); // AvId (2 bytes)
        buffer.putUInt16(value.length); // AvLen (2 bytes)
        buffer.putRawBytes(value); // Value (AvLen bytes)
    }

    @Override
    public AvPair<byte[]> read(Buffer<?> buffer) throws BufferException {
        int length = buffer.readUInt16(); // AvLen (2 bytes)
        this.value = buffer.readRawBytes(length); // Value (AvLen bytes)
        return this;
    }
}
