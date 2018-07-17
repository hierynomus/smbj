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

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.mssmb2.SMB2OplockBreakLevel;
import com.hierynomus.smb.SMBBuffer;

/**
 * [MS-SMB2].pdf 2.2.24 SMB2 OPLOCK_BREAK Acknowledgment
 */
public class SMB2OplockBreakAcknowledgment extends SMB2OplockBreak {

    public SMB2OplockBreakAcknowledgment(SMB2Dialect negotiatedDialect, long sessionId, long treeId, SMB2OplockBreakLevel oplockLevel, SMB2FileId fileId) {
        super(24, negotiatedDialect, sessionId, treeId);
        this.oplockLevel = oplockLevel;
        this.fileId = fileId;
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(structureSize); // StructureSize (2 bytes)
        buffer.putByte((byte)oplockLevel.getValue()); // OpLockLevel (1 byte)
        buffer.putReserved1(); // Reserved (1 bytes)
        buffer.putReserved4(); // Reserved (4 bytes)
        fileId.write(buffer);  // FileId (16 bytes)
    }
}
