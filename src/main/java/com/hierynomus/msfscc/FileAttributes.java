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
package com.hierynomus.msfscc;

import com.hierynomus.protocol.commons.EnumWithValue;

/**
 * [MS-FSCC].pdf 2.6 File Attributes.
 * <p/>
 * The following attributes are defined for files and directories. They can be used in any combination unless noted in
 * the description of the attribute's meaning. There is no file attribute with the value 0x00000000 because a value of
 * 0x00000000 in the FileAttributes field means that the file attributes for this file MUST NOT be changed when setting
 * basic information for the file.
 */
public enum FileAttributes implements EnumWithValue<FileAttributes> {
    /**
     * A file or directory that requires to be archived. Applications use this attribute to mark files for backup or removal.
     */
    FILE_ATTRIBUTE_ARCHIVE(0x00000020L),
    /**
     * A file or directory that is compressed. For a file, all of the data in the file is compressed. For a directory,
     * compression is the default for newly created files and subdirectories.
     */
    FILE_ATTRIBUTE_COMPRESSED(0x00000800L),
    /**
     * This item is a directory.
     */
    FILE_ATTRIBUTE_DIRECTORY(0x00000010L),
    /**
     * A file or directory that is encrypted. For a file, all data streams in the file are encrypted.
     * For a directory, encryption is the default for newly created files and subdirectories.
     */
    FILE_ATTRIBUTE_ENCRYPTED(0x00004000L),
    /**
     * A file or directory that is hidden. Files and directories marked with this attribute do not appear in an ordinary directory listing.
     */
    FILE_ATTRIBUTE_HIDDEN(0x00000002L),
    /**
     * A file that does not have other attributes set. This flag is used to clear all other flags by specifying it with no other flags set.
     * This flag MUST be ignored if other flags are set.
     */
    FILE_ATTRIBUTE_NORMAL(0x00000080L),
    /**
     * A file or directory that is not indexed by the content indexing service.
     */
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED(0x00002000L),
    /**
     * The data in this file is not available immediately. This attribute indicates that the file data is physically moved to offline storage.
     * This attribute is used by Remote Storage, which is hierarchical storage management software.
     */
    FILE_ATTRIBUTE_OFFLINE(0x00001000L),
    /**
     * A file or directory that is read-only. For a file, applications can read the file but cannot write to it or delete it.
     * For a directory, applications cannot delete it, but applications can create and delete files from that directory.
     */
    FILE_ATTRIBUTE_READONLY(0x00000001L),
    /**
     * A file or directory that has an associated reparse point.
     */
    FILE_ATTRIBUTE_REPARSE_POINT(0x00000400L),
    /**
     * A file that is a sparse file.
     */
    FILE_ATTRIBUTE_SPARSE_FILE(0x00000200L),
    /**
     * A file or directory that the operating system uses a part of or uses exclusively.
     */
    FILE_ATTRIBUTE_SYSTEM(0x00000004L),
    /**
     * A file that is being used for temporary storage. The operating system may choose to store this file's data in memory rather than on mass storage,
     * writing the data to mass storage only if data remains in the file when the file is closed.
     */
    FILE_ATTRIBUTE_TEMPORARY(0x00000100L),
    /**
     * A file or directory that is configured with integrity support. For a file, all data streams in the file have integrity support.
     * For a directory, integrity support is the default for newly created files and subdirectories, unless the caller specifies otherwise.
     */
    FILE_ATTRIBUTE_INTEGRITY_STREAM(0x00008000L),
    /**
     * A file or directory that is configured to be excluded from the data integrity scan. For a directory configured with FILE_ATTRIBUTE_NO_SCRUB_DATA,
     * the default for newly created files and subdirectories is to inherit the FILE_ATTRIBUTE_NO_SCRUB_DATA attribute.
     */
    FILE_ATTRIBUTE_NO_SCRUB_DATA(0x00020000L);

    private long value;

    FileAttributes(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
