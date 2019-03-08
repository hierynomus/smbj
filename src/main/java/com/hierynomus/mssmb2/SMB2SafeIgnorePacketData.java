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
package com.hierynomus.mssmb2;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

public class SMB2SafeIgnorePacketData extends SMB2PacketData {

    public SMB2SafeIgnorePacketData() throws Buffer.BufferException {
        this(null);
    }

    private SMB2SafeIgnorePacketData(byte[] data) throws Buffer.BufferException {
        super(data);
    }

    public long getSequenceNumber() {
        return 0L;
    }

    protected boolean isSuccess() {
        return false;
    }

    protected void readHeader() throws Buffer.BufferException {
        // do nothing
    }

    @Override
    public SMB2Header getHeader() {
        return null;
    }

    @Override
    public SMBBuffer getDataBuffer() {
        return null;
    }
}
