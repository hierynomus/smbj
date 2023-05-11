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

public class AvPairSingleHost extends AvPair<byte[]> {
    private byte[] machineID;

    AvPairSingleHost() {
        super(AvId.MsvAvSingleHost);
    }

    public AvPairSingleHost read(Buffer<?> buffer) throws BufferException {
        buffer.readUInt16(); // AvLen (2 bytes)
        buffer.readUInt32(); // Size (4 bytes)
        buffer.skip(4); // Z (4 bytes)
        this.value = buffer.readRawBytes(8); // CustomData (8 bytes)
        this.machineID = buffer.readRawBytes(32); // MachineID (32 bytes)
        return this;
    }

    @Override
    public void write(Buffer<?> buffer) {
        buffer.putUInt16((int) this.avId.getValue()); // AvId (2 bytes)
        buffer.putUInt16(48); // AvLen (2 bytes)
        buffer.putUInt32(48); // Size (4 bytes)
        buffer.putUInt32(0); // Z (4 bytes)
        buffer.putRawBytes(this.value); // CustomData (8 bytes)
        buffer.putRawBytes(this.machineID); // MachineID (32 bytes)
    }
}
