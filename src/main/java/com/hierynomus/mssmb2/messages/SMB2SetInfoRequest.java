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

import com.hierynomus.msdtyp.SecurityInformation;
import com.hierynomus.msfscc.FileInformationClass;
import com.hierynomus.mssmb2.*;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.smb.SMBBuffer;

import java.util.Set;

/**
 * [MS-SMB2].pdf 2.2.39 SMB2 SET_INFO Request
 */
public class SMB2SetInfoRequest extends SMB2Packet {

    private final SMB2FileId fileId;
    private final SMB2InfoType infoType;
    private final FileInformationClass fileInfoClass;
    private final byte[] buffer;
    private final Set<SecurityInformation> securityInformation;

    public SMB2SetInfoRequest(
        SMB2Dialect negotiatedDialect, long sessionId, long treeId,
        SMB2InfoType infoType, SMB2FileId fileId,
        FileInformationClass fileInfoClass,
        Set<SecurityInformation> securityInformation, byte[] buffer
    ) {
        super(33, negotiatedDialect, SMB2MessageCommandCode.SMB2_SET_INFO, sessionId, treeId);
        this.fileId = fileId;
        this.infoType = infoType;
        this.fileInfoClass = fileInfoClass;
        this.buffer = buffer == null ? new byte[0] : buffer;
        this.securityInformation = securityInformation;
    }

    /**
     * @param smbBuffer
     */
    @Override
    protected void writeTo(SMBBuffer smbBuffer) {
        smbBuffer.putUInt16(structureSize); // StructureSize (2 bytes)
        smbBuffer.putByte((byte) infoType.getValue()); // InfoType (1 byte)
        smbBuffer.putByte(fileInfoClass == null ? 0 : (byte) fileInfoClass.getValue()); // FileInfoClass (1 byte)
        int offset = SMB2Header.STRUCTURE_SIZE + 32;
        smbBuffer.putUInt32(buffer.length); // BufferLength (4 bytes)
        smbBuffer.putUInt16(offset); // BufferOffset (2 bytes)
        smbBuffer.putReserved2(); // Reserved (2 bytes)
        smbBuffer.putUInt32(securityInformation == null ? 0 : EnumWithValue.EnumUtils.toLong(securityInformation)); // AdditionalInformation (4 bytes)
        fileId.write(smbBuffer);  // FileId (16 bytes)
        smbBuffer.putRawBytes(buffer); // Buffer (variable)
    }

    public enum SMB2InfoType implements EnumWithValue<SMB2InfoType> {
        SMB2_0_INFO_FILE(0x01L),
        SMB2_0_INFO_FILESYSTEM(0x02L),
        SMB2_0_INFO_SECURITY(0x03L),
        SMB2_0_INFO_QUOTA(0x04L);

        private long value;

        SMB2InfoType(long value) {
            this.value = value;
        }

        public long getValue() {
            return value;
        }
    }

}
