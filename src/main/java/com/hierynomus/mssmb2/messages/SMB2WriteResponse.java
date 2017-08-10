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
package com.hierynomus.mssmb2.messages;

import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

/**
 * [MS-SMB2].pdf 2.2.22 SMB2 Write Response
 */
public class SMB2WriteResponse extends SMB2Packet {

    private long bytesWritten;

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        buffer.skip(2); // StructureSize (2 bytes)
        buffer.skip(2); // Reserved (2 bytes)
        bytesWritten = buffer.readUInt32(); // Count (4 bytes)
        buffer.skip(4); // Remaining (4 bytes) - Reserved do not use
        buffer.skip(2); // WriteChannelInfoOffset (2 bytes) - Reserved do not use
        buffer.skip(2); // WriteChannelInfoLength (2 bytes) - Reserved do not use
    }

    public long getBytesWritten() {
        return bytesWritten;
    }
}
