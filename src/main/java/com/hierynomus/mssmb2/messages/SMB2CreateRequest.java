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

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.mssmb2.*;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.common.SmbPath;

import java.util.Set;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.ensureNotNull;
import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toLong;

/**
 * [MS-SMB2].pdf 2.2.13 SMB2 CREATE Request
 * <p>
 */
public class SMB2CreateRequest extends SMB2Packet {

    private final Set<FileAttributes> fileAttributes;
    private final Set<SMB2ShareAccess> shareAccess;
    private final SMB2CreateDisposition createDisposition;
    private final Set<SMB2CreateOptions> createOptions;
    private final SmbPath path;
    private final Set<AccessMask> accessMask;
    private final SMB2ImpersonationLevel impersonationLevel;
    private final SMB2OplockLevel oplockLevel;

    @SuppressWarnings("PMD.ExcessiveParameterList")
    public SMB2CreateRequest(SMB2Dialect smbDialect,
                             long sessionId, long treeId,
                             SMB2OplockLevel oplockLevel,
                             SMB2ImpersonationLevel impersonationLevel,
                             Set<AccessMask> accessMask,
                             Set<FileAttributes> fileAttributes,
                             Set<SMB2ShareAccess> shareAccess, SMB2CreateDisposition createDisposition,
                             Set<SMB2CreateOptions> createOptions, SmbPath path) {
        super(57, smbDialect, SMB2MessageCommandCode.SMB2_CREATE, sessionId, treeId);
        this.oplockLevel = ensureNotNull(oplockLevel, SMB2OplockLevel.SMB2_OPLOCK_LEVEL_NONE);
        this.impersonationLevel = ensureNotNull(impersonationLevel, SMB2ImpersonationLevel.Identification);
        this.accessMask = accessMask;
        this.fileAttributes = ensureNotNull(fileAttributes, FileAttributes.class);
        this.shareAccess = ensureNotNull(shareAccess, SMB2ShareAccess.class);
        this.createDisposition = ensureNotNull(createDisposition, SMB2CreateDisposition.FILE_SUPERSEDE);
        this.createOptions = ensureNotNull(createOptions, SMB2CreateOptions.class);
        this.path = path;
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(structureSize); // StructureSize (2 bytes)
        buffer.putByte((byte) 0); // SecurityFlags (1 byte) - Reserved
        buffer.putByte((byte)oplockLevel.getValue());  // RequestedOpLockLevel (1 byte)
        buffer.putUInt32(impersonationLevel.getValue()); // ImpersonationLevel (4 bytes) - Identification
        buffer.putReserved(8); // SmbCreateFlags (8 bytes)
        buffer.putReserved(8); // Reserved (8 bytes)
        buffer.putUInt32(toLong(accessMask)); // DesiredAccess (4 bytes)
        buffer.putUInt32(toLong(fileAttributes)); // FileAttributes (4 bytes)
        buffer.putUInt32(toLong(shareAccess)); // ShareAccess (4 bytes)
        buffer.putUInt32(createDisposition.getValue()); // CreateDisposition (4 bytes)
        buffer.putUInt32(toLong(createOptions)); // CreateOptions (4 bytes)
        int offset = SMB2Header.STRUCTURE_SIZE + structureSize - 1; // The structureSize is including the minimum of 1 byte for the fileName

        byte[] nameBytes;
        String fileName = path.getPath();
        if (fileName == null || fileName.trim().length() == 0) {
            // If the path part of the SmbPath is `null`, this indicates the root of the share
            buffer.putUInt16(offset); // NameOffset (4 bytes)
            buffer.putUInt16(0); // NameLength (4 bytes)
            // For empty names(root directory) Windows requires
            // us to use a offset and in that offset have atleast a byte, since it affects alignment
            // set the variable later.
            nameBytes = new byte[1];
        } else {
            nameBytes = SMB2Functions.unicode(fileName);
            buffer.putUInt16(offset); // NameOffset (4 bytes)
            buffer.putUInt16(nameBytes.length); // NameLength (4 bytes)
        }

        // Create Contexts
        buffer.putUInt32(0); // CreateContextsOffset (4 bytes)
        buffer.putUInt32(0); // CreateContextsLength (4 bytes)

        buffer.putRawBytes(nameBytes);
    }

    public SmbPath getPath() {
        return path;
    }
}
