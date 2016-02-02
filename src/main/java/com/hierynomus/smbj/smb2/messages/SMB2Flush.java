/*
 * Copyright (C)2016 - Jeroen van Erp <jeroen@hierynomus.com>
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
package com.hierynomus.smbj.smb2.messages;

import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.smb2.SMB2FileId;
import com.hierynomus.smbj.smb2.SMB2MessageCommandCode;
import com.hierynomus.smbj.smb2.SMB2Packet;

/**
 * [MS-SMB2].pdf 2.2.17 SMB2 FLUSH Request / 2.2.18 SMB2 FLUSH Response
 */
public class SMB2Flush extends SMB2Packet {
    private SMB2FileId fileId;

    public SMB2Flush() {
    }

    public SMB2Flush(long messageId) {
        super(messageId, SMB2MessageCommandCode.SMB2_FLUSH);
    }

    @Override
    protected void writeMessage() {
        putUInt16(24); // StructureSize (2 bytes)
        putReserved(2); // Reserved1 (2 bytes)
        putReserved4(); // Reserved2 (4 bytes)
        fileId.write(this);
    }

    @Override
    protected void readMessage(SMBBuffer buffer) throws BufferException {
        buffer.readUInt16(); // StructureSize (2 bytes)
        buffer.skip(2); // Reserved (2 bytes)
    }

    public void setFileId(SMB2FileId fileId) {
        this.fileId = fileId;
    }
}
