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

import com.hierynomus.msfscc.FileInformationClass;
import com.hierynomus.mssmb2.*;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.smb.SMBBuffer;

import java.util.Set;

/**
 * [MS-SMB2].pdf 2.2.33 SMB2 QUERY DIRECTORY Request
 * <p>
 */
public class SMB2QueryDirectoryRequest extends SMB2MultiCreditPacket {
    private FileInformationClass fileInformationClass;

    private final Set<SMB2QueryDirectoryFlags> flags;
    private final long fileIndex;
    private final SMB2FileId fileId;
    private final String searchPattern;

    public SMB2QueryDirectoryRequest(SMB2Dialect smbDialect,
                                     long sessionId, long treeId,
                                     SMB2FileId fileId,
                                     FileInformationClass fileInformationClass,
                                     Set<SMB2QueryDirectoryFlags> flags,
                                     long fileIndex,
                                     String searchPattern,
                                     int maxBufferSize) {

        super(33, smbDialect, SMB2MessageCommandCode.SMB2_QUERY_DIRECTORY, sessionId, treeId, maxBufferSize);
        this.fileInformationClass = fileInformationClass;
        this.flags = flags;
        this.fileIndex = fileIndex;
        this.fileId = fileId;
        // The Spec says the searchPattern is optional
        // but getting invalid parameter status, so use a pattern of "*" if no pattern.
        this.searchPattern = searchPattern == null ? "*" : searchPattern;
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(structureSize); // StructureSize (2 bytes)
        buffer.putByte((byte) fileInformationClass.getValue()); // FileInformationClass (1 byte)
        buffer.putByte((byte) EnumWithValue.EnumUtils.toLong(flags)); // Flags (1 byte)
        buffer.putUInt32(fileIndex); // FileIndex (4 bytes)
        fileId.write(buffer); // FileId (16 bytes)
        int offset = SMB2Header.STRUCTURE_SIZE + 32;
        buffer.putUInt16(offset); // FileNameOffset (2 bytes)
        buffer.putUInt16(searchPattern.length() * 2); // FileNameLength (2 bytes)
        buffer.putUInt32(Math.min(getMaxPayloadSize(), SINGLE_CREDIT_PAYLOAD_SIZE * getCreditsAssigned())); // OutputBufferLength (4 bytes)
        buffer.putString(searchPattern); // Buffer (variable)
    }

    public enum SMB2QueryDirectoryFlags implements EnumWithValue<SMB2QueryDirectoryFlags> {
        SMB2_RESTART_SCANS(0x01),
        SMB2_RETURN_SINGLE_ENTRY(0x02),
        SMB2_INDEX_SPECIFIED(0x04),
        SMB2_REOPEN(0x10);

        private long value;

        SMB2QueryDirectoryFlags(long value) {
            this.value = value;
        }

        public long getValue() {
            return value;
        }
    }
}
