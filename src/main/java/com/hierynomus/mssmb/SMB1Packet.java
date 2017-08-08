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
package com.hierynomus.mssmb;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smb.SMBPacket;

public class SMB1Packet extends SMBPacket<SMB1Header> {
    protected SMB1Packet() {
        super(new SMB1Header());
    }

    @Override
    public final void write(SMBBuffer buffer) {
        header.writeTo(buffer);
        writeTo(buffer);
    }

    @Override
    public void read(SMBBuffer buffer) throws Buffer.BufferException {
        throw new UnsupportedOperationException("Receiving SMBv1 Messages not supported in SMBJ");
    }


    /**
     * Write the message fields into the buffer, as specified in the MS-SMB specification.
     *
     * @param buffer
     */
    protected void writeTo(SMBBuffer buffer) {
        throw new UnsupportedOperationException("Should be implemented by specific message type");
    }

}
