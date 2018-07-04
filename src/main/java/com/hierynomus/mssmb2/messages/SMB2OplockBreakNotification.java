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

import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2OplockBreakLevel;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

/**
 * [MS-SMB2].pdf 2.2.23 SMB2 OPLOCK_BREAK Notification
 */
public class SMB2OplockBreakNotification extends SMB2Packet {

    private SMB2OplockBreakLevel oplockLevel;
    private SMB2FileId fileId;

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        buffer.readUInt16(); // StructureSize (2 bytes)
        oplockLevel = EnumWithValue.EnumUtils.valueOf(buffer.readByte(), SMB2OplockBreakLevel.class, SMB2OplockBreakLevel.SMB2_OPLOCK_LEVEL_NONE); // OpLockLevel (1 byte)
        buffer.readByte(); // Reserved (1 byte)
        buffer.skip(4); // Reserved2 (4 bytes)
        fileId = SMB2FileId.read(buffer); // FileId (16 bytes)
    }

    public SMB2OplockBreakLevel getOplockLevel() {
        return oplockLevel;
    }

    public SMB2FileId getFileId() {
        return fileId;
    }
}
