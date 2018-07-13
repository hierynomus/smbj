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
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

import java.util.Set;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toEnumSet;

/**
 * [MS-SMB2].pdf 2.2.14 SMB2 CREATE Response
 */
public class SMB2CreateResponse extends SMB2Packet {

    private SMB2OplockLevel oplockLevel;
    private SMB2CreateAction createAction;
    private FileTime creationTime;
    private FileTime lastAccessTime;
    private FileTime lastWriteTime;
    private FileTime changeTime;
    private long allocationSize;
    private long endOfFile;
    private Set<FileAttributes> fileAttributes;
    private SMB2FileId fileId;

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        buffer.readUInt16(); // StructureSize (2 bytes)
        oplockLevel = EnumWithValue.EnumUtils.valueOf(buffer.readByte(), SMB2OplockLevel.class, SMB2OplockLevel.SMB2_OPLOCK_LEVEL_NONE); // OpLockLevel (1 byte)
        buffer.readByte(); // Flags (1 byte) - Only for 3.x else Reserved
        createAction = EnumWithValue.EnumUtils.valueOf(buffer.readUInt32(), SMB2CreateAction.class, null); // CreateAction (4 bytes)
        creationTime = MsDataTypes.readFileTime(buffer); // CreationTime (8 bytes)
        lastAccessTime = MsDataTypes.readFileTime(buffer); // LastAccessTime (8 bytes)
        lastWriteTime = MsDataTypes.readFileTime(buffer); // LastWriteTime (8 bytes)
        changeTime = MsDataTypes.readFileTime(buffer); // ChangeTime (8 bytes)
        allocationSize = buffer.readLong(); // AllocationSize (8 bytes)
        endOfFile = buffer.readUInt64(); // EndOfFile (8 bytes)
        fileAttributes = toEnumSet(buffer.readUInt32(), FileAttributes.class); // FileAttributes (4 bytes)
        buffer.skip(4); // Reserved2 (4 bytes)
        fileId = SMB2FileId.read(buffer); // FileId (16 bytes)

        // Ignore create contexts and the buffer.
        buffer.readUInt32();// CreateContextsOffset (4 bytes)
        buffer.readUInt32();// CreateContextsLength (4 bytes)
    }

    public SMB2OplockLevel getOplockLevel() {
        return oplockLevel;
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

    public long getAllocationSize() {
        return allocationSize;
    }

    public long getEndOfFile() {
        return endOfFile;
    }

    public Set<FileAttributes> getFileAttributes() {
        return fileAttributes;
    }

    public SMB2FileId getFileId() {
        return fileId;
    }
}
