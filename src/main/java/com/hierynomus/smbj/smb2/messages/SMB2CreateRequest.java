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

import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.smb2.SMB2CreateDisposition;
import com.hierynomus.smbj.smb2.SMB2CreateOptions;
import com.hierynomus.smbj.smb2.SMB2Dialect;
import com.hierynomus.smbj.smb2.SMB2DirectoryAccessMask;
import com.hierynomus.smbj.smb2.SMB2Header;
import com.hierynomus.smbj.smb2.SMB2MessageCommandCode;
import com.hierynomus.smbj.smb2.SMB2Packet;
import com.hierynomus.smbj.smb2.SMB2ShareAccess;

import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.EnumSet;

/**
 * [MS-SMB2].pdf 2.2.13 SMB2 CREATE Request
 * <p>
 * TODO
 */
public class SMB2CreateRequest extends SMB2Packet {

    private final SMB2Dialect dialect;
    private final EnumSet<FileAttributes> fileAttributes;
    private final EnumSet<SMB2ShareAccess> shareAccess;
    private final SMB2CreateDisposition createDisposition;
    private final EnumSet<SMB2CreateOptions> createOptions;
    private final String fileName; // Null to indicate the root of share
    private final EnumSet<SMB2DirectoryAccessMask> directoryAccessMask;

    public SMB2CreateRequest(SMB2Dialect smbDialect,
                             long sessionId, long treeId,
                             EnumSet<SMB2DirectoryAccessMask> directoryAccessMask,
                             EnumSet<FileAttributes> fileAttributes,
                             EnumSet<SMB2ShareAccess> shareAccess, SMB2CreateDisposition createDisposition,
                             EnumSet<SMB2CreateOptions> createOptions, String fileName) {

        super(smbDialect, SMB2MessageCommandCode.SMB2_CREATE);
        getHeader().setSessionId(sessionId);
        getHeader().setTreeId(treeId);
        this.dialect = smbDialect;
        this.directoryAccessMask = directoryAccessMask;
        this.fileAttributes = fileAttributes;
        this.shareAccess = shareAccess;
        this.createDisposition = createDisposition;
        this.createOptions = createOptions;
        this.fileName = fileName;

    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(57); // StructureSize (2 bytes)
        buffer.putByte((byte) 0); // SecurityFlags (1 byte) - Reserved
        buffer.putByte((byte) 0);  // Req OpLock Level (1 byte) - None
        buffer.putUInt32(1); // Impersonation Level (4 bytes) - Identification
        buffer.putReserved(8); // SmbCreateFlags (8 bytes)
        buffer.putReserved(8); // Reserved (8 bytes)
        buffer.putUInt32(EnumWithValue.EnumUtils.toLong(directoryAccessMask)); // Access Mask (4 bytes) - GENERIC_ALL
        buffer.putUInt32(EnumWithValue.EnumUtils.toLong(fileAttributes)); // File Attributes (4 bytes)
        buffer.putUInt32(EnumWithValue.EnumUtils.toLong(shareAccess)); // Share Access (4 bytes)
        buffer.putUInt32(createDisposition.getValue()); // Create Disposition (4 bytes)
        buffer.putUInt32(EnumWithValue.EnumUtils.toLong(createOptions)); // Create Options (4 bytes)
        int offset = SMB2Header.STRUCTURE_SIZE + 56;
        try {
            byte[] nameBytes = (fileName == null) ? new byte[0] : fileName.getBytes(UNI_ENCODING);
            buffer.putUInt16(offset); // Offset
            buffer.putUInt16(nameBytes.length); // Length

            // Create Contexts
            buffer.putUInt32(0); // Offset
            buffer.putUInt32(0); // Length

            if (nameBytes.length > 0) buffer.putRawBytes(nameBytes);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Unexpected exception ", e);
        }
    }
}
