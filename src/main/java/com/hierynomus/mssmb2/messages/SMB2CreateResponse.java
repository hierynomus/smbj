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

import com.hierynomus.msdtyp.FileTime;
import com.hierynomus.msdtyp.MsDataTypes;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.mssmb2.SMB2CreateAction;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2OplockLevel;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.messages.create.SMB2CreateContext;
import com.hierynomus.mssmb2.messages.create.SMB2LeaseCreateContext;
import com.hierynomus.mssmb2.messages.create.SMB2LeaseResponseContext;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toEnumSet;

/**
 * [MS-SMB2].pdf 2.2.14 SMB2 CREATE Response
 */
public class SMB2CreateResponse extends SMB2Packet {

    private SMB2CreateAction createAction;
    private FileTime creationTime;
    private FileTime lastAccessTime;
    private FileTime lastWriteTime;
    private FileTime changeTime;
    private Set<FileAttributes> fileAttributes;
    private SMB2FileId fileId;
    private SMB2OplockLevel oplockLevel = SMB2OplockLevel.SMB2_OPLOCK_LEVEL_NONE;
    private int flags;
    private List<SMB2CreateContext> createContexts = Collections.emptyList();

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        buffer.readUInt16(); // StructureSize (2 bytes)
        oplockLevel = EnumWithValue.EnumUtils.valueOf(buffer.readByte() & 0xFF, SMB2OplockLevel.class, SMB2OplockLevel.SMB2_OPLOCK_LEVEL_NONE); // OplockLevel (1 byte)
        flags = buffer.readByte() & 0xFF; // Flags (1 byte) - Only for 3.x else Reserved
        createAction = EnumWithValue.EnumUtils.valueOf(buffer.readUInt32(), SMB2CreateAction.class, null); // CreateAction (4 bytes)
        creationTime = MsDataTypes.readFileTime(buffer); // CreationTime (8 bytes)
        lastAccessTime = MsDataTypes.readFileTime(buffer); // LastAccessTime (8 bytes)
        lastWriteTime = MsDataTypes.readFileTime(buffer); // LastWriteTime (8 bytes)
        changeTime = MsDataTypes.readFileTime(buffer); // ChangeTime (8 bytes)
        buffer.readRawBytes(8); // AllocationSize (8 bytes) - Ignore
        buffer.readRawBytes(8); // EndOfFile (8 bytes)
        fileAttributes = toEnumSet(buffer.readUInt32(), FileAttributes.class); // FileAttributes (4 bytes)
        buffer.skip(4); // Reserved2 (4 bytes)
        fileId = SMB2FileId.read(buffer); // FileId (16 bytes)

        long createContextsOffset = buffer.readUInt32(); // CreateContextsOffset (4 bytes)
        long createContextsLength = buffer.readUInt32(); // CreateContextsLength (4 bytes)
        if (createContextsLength > 0) {
            // Offset is relative to the start of the SMB2 header (matters when compounded).
            int base = getHeader().getHeaderStartPosition();
            createContexts = SMB2CreateContext.readAll(buffer, base + (int) createContextsOffset, (int) createContextsLength);
        }
    }

    public SMB2OplockLevel getOplockLevel() {
        return oplockLevel;
    }

    public int getFlags() {
        return flags;
    }

    public List<SMB2CreateContext> getCreateContexts() {
        return createContexts;
    }

    /** The granted lease ("RqLs") response context, or {@code null} if the server granted no lease. */
    public SMB2LeaseResponseContext getLeaseResponseContext() throws Buffer.BufferException {
        for (SMB2CreateContext ctx : createContexts) {
            if (Arrays.equals(ctx.getName(), SMB2LeaseCreateContext.NAME)) {
                return SMB2LeaseResponseContext.from(ctx);
            }
        }
        return null;
    }

    public SMB2CreateAction getCreateAction() {
        return createAction;
    }

    public FileTime getCreationTime() {
        return creationTime;
    }

    public FileTime getLastAccessTime() {
        return lastAccessTime;
    }

    public FileTime getLastWriteTime() {
        return lastWriteTime;
    }

    public FileTime getChangeTime() {
        return changeTime;
    }

    public Set<FileAttributes> getFileAttributes() {
        return fileAttributes;
    }

    public SMB2FileId getFileId() {
        return fileId;
    }

    public void setFileAttributes(Set<FileAttributes> fileAttributes) {
        this.fileAttributes = fileAttributes;
    }

    public void setFileId(SMB2FileId fileId) {
        this.fileId = fileId;
    }
}
