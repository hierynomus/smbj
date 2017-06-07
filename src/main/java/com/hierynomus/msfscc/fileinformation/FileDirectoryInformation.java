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

import com.hierynomus.msdtyp.FileTime;

public class FileDirectoryInformation extends FileDirectoryQueryableInformation {
    private final FileTime creationTime;
    private final FileTime lastAccessTime;
    private final FileTime lastWriteTime;
    private final FileTime changeTime;
    private final long endOfFile;
    private final long allocationSize;
    private final long fileAttributes;

    @SuppressWarnings("PMD.ExcessiveParameterList")
    FileDirectoryInformation(long nextOffset, long fileIndex, String fileName, FileTime creationTime, FileTime lastAccessTime, FileTime lastWriteTime, FileTime changeTime, long endOfFile, long allocationSize, long fileAttributes) {
        super(nextOffset, fileIndex, fileName);
        this.creationTime = creationTime;
        this.lastAccessTime = lastAccessTime;
        this.lastWriteTime = lastWriteTime;
        this.changeTime = changeTime;
        this.endOfFile = endOfFile;
        this.allocationSize = allocationSize;
        this.fileAttributes = fileAttributes;
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

    public long getEndOfFile() {
        return endOfFile;
    }

    public long getAllocationSize() {
        return allocationSize;
    }

    public long getFileAttributes() {
        return fileAttributes;
    }
}
