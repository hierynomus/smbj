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
package com.hierynomus.msfscc.fileinformation;

import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.protocol.commons.EnumWithValue;

import java.util.Date;

public class FileInfo {

    private byte[] fileId; // This is not the SMB2FileId, but not sure what one can do with this id.
    private String fileName;
    private final Date creationTime;
    private final Date lastAccessTime;
    private final Date lastWriteTime;
    private final Date changeTime;
    private long fileAttributes;
    private long fileSize;
    private long accessMask;


    FileInfo(String fileName, byte[] fileId, Date creationTime, Date lastAccessTime, Date lastWriteTime, Date changeTime, long fileAttributes, long fileSize, long accessMask) {
        this.fileName = fileName;
        this.fileId = fileId;
        this.creationTime = creationTime;
        this.lastAccessTime = lastAccessTime;
        this.lastWriteTime = lastWriteTime;
        this.changeTime = changeTime;
        this.fileAttributes = fileAttributes;
        this.fileSize = fileSize;
        this.accessMask = accessMask;
    }

    public byte[] getFileId() {
        return fileId;
    }

    public String getFileName() {
        return fileName;
    }

    public long getFileAttributes() {
        return fileAttributes;
    }

    public long getFileSize() {
        return fileSize;
    }

    public long getAccessMask() {
        return accessMask;
    }

    public Date getCreationTime() {
        return copyOf(creationTime);
    }

    public Date getLastAccessTime() {
        return copyOf(lastAccessTime);
    }

    public Date getLastWriteTime() {
        return copyOf(lastWriteTime);
    }

    public Date getChangeTime() {
        return copyOf(changeTime);
    }

    private Date copyOf(Date date) {
        return date != null ? new Date(date.getTime()) : null;
    }

    @Override
    public String toString() {
        return "FileInfo{" +
            "fileName='" + fileName + '\'' +
            "fileSize='" + fileSize + '\'' +
            ", fileAttributes=" + EnumWithValue.EnumUtils.toEnumSet(fileAttributes, FileAttributes.class) +
            '}';
    }
}
