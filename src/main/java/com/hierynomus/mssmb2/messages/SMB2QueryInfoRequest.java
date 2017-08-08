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
import com.hierynomus.msfscc.FileSystemInformationClass;
import com.hierynomus.mssmb2.*;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.smb.SMBBuffer;

import java.util.Set;

/**
 * [MS-SMB2].pdf 2.2.37 SMB2 QUERY_INFO Request
 */
public class SMB2QueryInfoRequest extends SMB2Packet {

    long MAX_OUTPUT_BUFFER_LENGTH = 64 * 1024;

    private final SMB2FileId fileId;
    private final SMB2QueryInfoType infoType;
    private final FileInformationClass fileInformationClass;
    private final FileSystemInformationClass fileSystemInformationClass;
    private final byte[] inputBuffer;
    private final Set<SecurityInformation> securityInformation;

    public SMB2QueryInfoRequest(SMB2Dialect smbDialect,
                                long sessionId, long treeId,
                                SMB2FileId fileId, SMB2QueryInfoType infoType,
                                FileInformationClass fileInformationClass,
                                FileSystemInformationClass fileSystemInformationClass,
                                byte[] inputBuffer,
                                Set<SecurityInformation> securityInformation) {

        super(41, smbDialect, SMB2MessageCommandCode.SMB2_QUERY_INFO, sessionId, treeId);
        this.infoType = infoType;
        this.fileInformationClass = fileInformationClass;
        this.fileSystemInformationClass = fileSystemInformationClass;
        this.inputBuffer = inputBuffer;
        this.securityInformation = securityInformation;

        this.fileId = fileId;
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(structureSize); // StructureSize (2 bytes)
        buffer.putByte((byte) infoType.getValue()); // InfoType (1 byte)
        int BUFFER_OFFSET = SMB2Header.STRUCTURE_SIZE + 40;
        int offset = 0;
        switch (infoType) { // FileInfoClass 1 byte
            case SMB2_0_INFO_FILE:
                buffer.putByte((byte) fileInformationClass.getValue()); // FileInformationClass (1 byte)
                buffer.putUInt32(MAX_OUTPUT_BUFFER_LENGTH); // OutputBufferLength (4 bytes)
                if (fileInformationClass == FileInformationClass.FileFullEaInformation) {
                    buffer.putUInt16(offset); // InputBufferOffset (2 bytes)
                    buffer.putReserved2(); // Reserved (2 bytes)
                    buffer.putUInt32(inputBuffer.length); // Input Buffer length (4 bytes)
                    offset = BUFFER_OFFSET;
                } else {
                    buffer.putUInt16(0); // InputBufferOffset (2 bytes)
                    buffer.putReserved2(); // Reserved (2 bytes)
                    buffer.putUInt32(0); // Input Buffer length (4 bytes)
                }
                buffer.putUInt32(0); // Additional Information (4 bytes)
                buffer.putUInt32(0); // Flags (4 bytes)
                fileId.write(buffer); // FileId (16 bytes)
                break;
            case SMB2_0_INFO_FILESYSTEM:
                buffer.putByte((byte) fileSystemInformationClass.getValue()); // FileSystemInformationClass (1 byte)
                buffer.putUInt32(MAX_OUTPUT_BUFFER_LENGTH); // OutputBufferLength (4 bytes)
                buffer.putUInt16(0); // InputBufferOffset (2 bytes)
                buffer.putReserved2(); // Reserved (2 bytes)
                buffer.putUInt32(0); // Input Buffer length (4 bytes)
                buffer.putUInt32(0); // Additional Information (4 bytes)
                buffer.putUInt32(0); // Flags (4 bytes)
                fileId.write(buffer); // FileId (16 bytes)
                break;
            case SMB2_0_INFO_SECURITY:
                buffer.putByte((byte) 0);
                buffer.putUInt32(MAX_OUTPUT_BUFFER_LENGTH); // OutputBufferLength (4 bytes)
                buffer.putUInt16(0); // InputBufferOffset (2 bytes)
                buffer.putReserved2(); // Reserved (2 bytes)
                buffer.putUInt32(0); // Input Buffer length (4 bytes)
                buffer.putUInt32(EnumWithValue.EnumUtils.toLong(securityInformation)); // Additional Information (4 bytes)
                buffer.putUInt32(0); // Flags (4 bytes)
                fileId.write(buffer); // FileId (16 bytes)
                break;
            case SMB2_0_INFO_QUOTA:
                buffer.putByte((byte) 0);
                buffer.putUInt32(MAX_OUTPUT_BUFFER_LENGTH); // OutputBufferLength (4 bytes)
                buffer.putUInt16(offset); // InputBufferOffset (2 bytes)
                buffer.putReserved2(); // Reserved (2 bytes)
                buffer.putUInt32(inputBuffer.length); // Input Buffer length (4 bytes)
                buffer.putUInt32(0); // Additional Information (4 bytes)
                buffer.putUInt32(0); // Flags (4 bytes)
                fileId.write(buffer); // FileId (16 bytes)
                offset = BUFFER_OFFSET;
                break;
            default:
                throw new IllegalStateException("Unknown SMB2QueryInfoType: " + infoType);
        }
        if (offset > 0) {
            buffer.putRawBytes(inputBuffer);
        }
    }

    public enum SMB2QueryInfoType implements EnumWithValue<SMB2QueryInfoType> {
        SMB2_0_INFO_FILE(0x01),
        SMB2_0_INFO_FILESYSTEM(0x02),
        SMB2_0_INFO_SECURITY(0x03),
        SMB2_0_INFO_QUOTA(0x04);

        private long value;

        SMB2QueryInfoType(long value) {
            this.value = value;
        }

        public long getValue() {
            return value;
        }
    }
}
