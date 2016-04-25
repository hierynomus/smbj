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

public class FileInfo {

    private byte[] fileId; // This is not the SMB2FileId, but not sure what one can do with this id.
    private String fileName;
    private long fileAttributes;
    private long fileSize;
    private long accessMask;


    public FileInfo(String fileName, byte[] fileId, long fileAttributes, long fileSize, long accessMask) {
        this.fileName = fileName;
        this.fileId = fileId;
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

    @Override
    public String toString() {
        return "FileInfo{" +
                "fileName='" + fileName + '\'' +
                "fileSize='" + fileSize + '\'' +
                ", fileAttributes=" + EnumWithValue.EnumUtils.toEnumSet(fileAttributes, FileAttributes.class) +
                '}';
    }
}
