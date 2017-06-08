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

public class FileStandardInformation implements FileQueryableInformation {
    private long allocationSize;
    private long endOfFile;
    private long numberOfLinks;
    private boolean deletePending;
    private boolean directory;

    FileStandardInformation(long allocationSize, long endOfFile, long numberOfLinks, boolean deletePending, boolean directory) {
        this.allocationSize = allocationSize;
        this.endOfFile = endOfFile;
        this.numberOfLinks = numberOfLinks;
        this.deletePending = deletePending;
        this.directory = directory;
    }

    public long getAllocationSize() {
        return allocationSize;
    }

    public long getEndOfFile() {
        return endOfFile;
    }

    public long getNumberOfLinks() {
        return numberOfLinks;
    }

    public boolean isDeletePending() {
        return deletePending;
    }

    public boolean isDirectory() {
        return directory;
    }
}
