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

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.smb2.SMB2FileId;
import com.hierynomus.smbj.smb2.SMB2MessageCommandCode;
import com.hierynomus.smbj.smb2.SMB2Packet;

import java.util.Date;

/**
 * [MS-SMB2].pdf 2.2.15 SMB2 CLOSE Request / 2.2.16 SMB2 CLOSE Response
 */
public class SMB2Close extends SMB2Packet {

    private SMB2FileId fileId;
    private Date creationTime;
    private Date lastAccessTime;
    private Date lastWriteTime;
    private Date changeTime;
    private long allocationSize;
    private long size;
    private byte[] fileAttributes;

    public SMB2Close() {
        super(SMB2MessageCommandCode.SMB2_CLOSE);
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(24); // StructureSize (2 bytes)
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
        creationTime = buffer.readDate(); // CreationTime (8 bytes)
        lastAccessTime = buffer.readDate(); // LastAccessTime (8 bytes)
        lastWriteTime = buffer.readDate(); // LastWriteTime (8 bytes)
        changeTime = buffer.readDate(); // ChangeTime (8 bytes)
        allocationSize = buffer.readUInt64(); // AllocationSize (8 bytes)
        size = buffer.readUInt64(); // EndOfFile (8 bytes)
        fileAttributes = buffer.readRawBytes(4); // FileAttributes (4 bytes)
        super.readMessage(buffer);
    }

    public Date getCreationTime() {
        return creationTime;
    }

    public Date getLastAccessTime() {
        return lastAccessTime;
    }

    public Date getLastWriteTime() {
        return lastWriteTime;
    }

    public Date getChangeTime() {
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
