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

import com.hierynomus.protocol.PacketData;
import com.hierynomus.protocol.commons.buffer.Buffer;

/**
 * The SMB Packet Data represents a partially deserialized SMB packet.
 * Only the header part is deserialized after which we can determine which packet
 * needs to be constructed.
 *
 * @param <H> The SMBHeader type
 */
public abstract class SMBPacketData<H extends SMBHeader> implements PacketData<SMBBuffer> {
    private H header;
    protected SMBBuffer dataBuffer;

    public SMBPacketData(H header, byte[] data) throws Buffer.BufferException {
        this.header = header;
        this.dataBuffer = new SMBBuffer(data);
        readHeader();
    }

    protected void readHeader() throws Buffer.BufferException {
        this.header.readFrom(dataBuffer);
    }

    public H getHeader() {
        return header;
    }

    @Override
    public SMBBuffer getDataBuffer() {
        return dataBuffer;
    }
}
