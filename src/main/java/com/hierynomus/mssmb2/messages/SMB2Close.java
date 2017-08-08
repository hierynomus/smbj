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
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

/**
 * [MS-SMB2].pdf 2.2.15 SMB2 CLOSE Request / 2.2.16 SMB2 CLOSE Response
 */
public class SMB2Close extends SMB2Packet {

    private SMB2FileId fileId;
    private FileTime creationTime;
    private FileTime lastAccessTime;
    private FileTime lastWriteTime;
    private FileTime changeTime;
    private long allocationSize;
    private long size;
    private byte[] fileAttributes;

    public SMB2Close() {
    }

    public SMB2Close(SMB2Dialect smbDialect, long sessionId, long treeId, SMB2FileId fileId) {
        super(24, smbDialect, SMB2MessageCommandCode.SMB2_CLOSE, sessionId, treeId);
        this.fileId = fileId;
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(structureSize); // StructureSize (2 bytes)
        buffer.putUInt16(0x01); // Flags (2 bytes) (SMB2_CLOSE_FLAGS_POSTQUERY_ATTRIB)
        buffer.putReserved4(); // Reserved (4 bytes)
        fileId.write(buffer); // FileId (16 bytes)
    }

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        buffer.readUInt16(); // StructureSize (2 bytes)
        // We set the Flags value 0x01 hardcoded, so the server should also echo that
        buffer.readUInt16(); // Flags (2 bytes)
        buffer.skip(4); // Reserved (4 bytes)
        creationTime = MsDataTypes.readFileTime(buffer); // CreationTime (8 bytes)
        lastAccessTime = MsDataTypes.readFileTime(buffer); // LastAccessTime (8 bytes)
        lastWriteTime = MsDataTypes.readFileTime(buffer); // LastWriteTime (8 bytes)
        changeTime = MsDataTypes.readFileTime(buffer); // ChangeTime (8 bytes)
        allocationSize = buffer.readUInt64(); // AllocationSize (8 bytes)
        size = buffer.readUInt64(); // EndOfFile (8 bytes)
        fileAttributes = buffer.readRawBytes(4); // FileAttributes (4 bytes)
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

    public long getSize() {
        return size;
    }

    public byte[] getFileAttributes() {
        return fileAttributes;
    }

    public void setFileId(SMB2FileId fileId) {
        this.fileId = fileId;
    }
}
