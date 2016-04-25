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
package com.hierynomus.smbj.smb2.messages;

import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.ntlm.functions.NtlmFunctions;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.smb2.*;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.util.EnumSet;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toLong;

/**
 * [MS-SMB2].pdf 2.2.13 SMB2 CREATE Request
 * <p>
 * TODO
 */
public class SMB2CreateRequest extends SMB2Packet {

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

        super(smbDialect, SMB2MessageCommandCode.SMB2_CREATE, sessionId, treeId);
        this.directoryAccessMask =
                directoryAccessMask == null ? EnumSet.noneOf(SMB2DirectoryAccessMask.class) : directoryAccessMask;
        this.fileAttributes =
                fileAttributes == null ? EnumSet.noneOf(FileAttributes.class) : fileAttributes;
        this.shareAccess =
                shareAccess == null ? EnumSet.noneOf(SMB2ShareAccess.class) : shareAccess;
        this.createDisposition = createDisposition;
        this.createOptions =
                createOptions == null ? EnumSet.noneOf(SMB2CreateOptions.class) : createOptions;
        this.fileName = fileName;

    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(57); // StructureSize (2 bytes)
        buffer.putByte((byte) 0); // SecurityFlags (1 byte) - Reserved
        buffer.putByte((byte) 0);  // RequestedOpLockLevel (1 byte) - None
        buffer.putUInt32(1); // ImpersonationLevel (4 bytes) - Identification
        buffer.putReserved(8); // SmbCreateFlags (8 bytes)
        buffer.putReserved(8); // Reserved (8 bytes)
        buffer.putUInt32(toLong(directoryAccessMask)); // DesiredAccess (4 bytes)
        buffer.putUInt32(toLong(fileAttributes)); // FileAttributes (4 bytes)
        buffer.putUInt32(toLong(shareAccess)); // ShareAccess (4 bytes)
        buffer.putUInt32(createDisposition == null ? 0 : createDisposition.getValue()); // CreateDisposition (4 bytes)
        buffer.putUInt32(toLong(createOptions)); // CreateOptions (4 bytes)
        int offset = SMB2Header.STRUCTURE_SIZE + 56;
        byte[] nameBytes = SMB2Functions.unicode(fileName);
        buffer.putUInt16(offset); // NameOffset (4 bytes)
        buffer.putUInt16(nameBytes.length); // NameLength (4 bytes)

        // Create Contexts
        buffer.putUInt32(0); // CreateContextsOffset (4 bytes)
        buffer.putUInt32(0); // CreateContextsLength (4 bytes)

        buffer.putRawBytes(nameBytes);
    }
}
