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

public class FileBasicInformation implements FileQueryableInformation, FileSettableInformation {
    /**
     * When setting file attributes, set a time field to this value to indicate to the server that it MUST NOT change the field.
     */
    public static final FileTime DONT_SET = new FileTime(0);

    /**
     * When setting file attributes, set a time field to this value to indicate to the server that it MUST NOT change the field for all subsequent operations on the same file handle.
     */
    public static final FileTime DONT_UPDATE = new FileTime(-1);

    private final FileTime creationTime;
    private final FileTime lastAccessTime;
    private final FileTime lastWriteTime;
    private final FileTime changeTime;
    private long fileAttributes;

    public FileBasicInformation(FileTime creationTime, FileTime lastAccessTime, FileTime lastWriteTime, FileTime changeTime, long fileAttributes) {
        this.creationTime = creationTime;
        this.lastAccessTime = lastAccessTime;
        this.lastWriteTime = lastWriteTime;
        this.changeTime = changeTime;
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

    public long getFileAttributes() {
        return fileAttributes;
    }
}
