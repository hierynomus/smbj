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
package com.hierynomus.smb;

import com.hierynomus.protocol.Packet;
import com.hierynomus.protocol.commons.buffer.Buffer;

public abstract class SMBPacket<D extends SMBPacketData<H>, H extends SMBHeader> implements Packet<SMBBuffer> {
    protected H header;

    public SMBPacket(H header) {
        this.header = header;
    }

    public H getHeader() {
        return header;
    }

    protected abstract void read(D packetData) throws Buffer.BufferException;

    @Override
    public final void read(SMBBuffer buffer) throws Buffer.BufferException {
        throw new UnsupportedOperationException("Call read(D extends PacketData<H>) instead of this method");
    }

}
