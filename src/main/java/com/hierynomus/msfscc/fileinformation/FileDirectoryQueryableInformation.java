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

public abstract class FileDirectoryQueryableInformation implements FileInformation {
    private final String fileName;
    private long nextOffset;
    private long fileIndex;

    public FileDirectoryQueryableInformation(long nextOffset, long fileIndex, String fileName) {
        this.nextOffset = nextOffset;
        this.fileIndex = fileIndex;
        this.fileName = fileName;
    }

    public long getNextOffset() {
        return nextOffset;
    }

    public long getFileIndex() {
        return fileIndex;
    }

    public String getFileName() {
        return fileName;
    }
}
