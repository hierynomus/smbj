/*
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
 * [MS-FSCC].pdf 2.6 File Attributes
 */
public enum FileAttributes implements EnumWithValue<FileAttributes> {
    FILE_ATTRIBUTE_ARCHIVE(0x00000020),
    FILE_ATTRIBUTE_COMPRESSED(0x00000800),
    FILE_ATTRIBUTE_DIRECTORY(0x00000010),
    FILE_ATTRIBUTE_ENCRYPTED(0x00004000),
    FILE_ATTRIBUTE_HIDDEN(0x00000002),
    FILE_ATTRIBUTE_NORMAL(0x00000080),
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED(0x00002000),
    FILE_ATTRIBUTE_OFFLINE(0x00001000),
    FILE_ATTRIBUTE_READONLY(0x00000001),
    FILE_ATTRIBUTE_REPARSE_POINT(0x00000400),
    FILE_ATTRIBUTE_SPARSE_FILE(0x00000200),
    FILE_ATTRIBUTE_SYSTEM(0x00000004),
    FILE_ATTRIBUTE_TEMPORARY(0x00000100),
    FILE_ATTRIBUTE_INTEGRITY_STREAM(0x00008000),
    FILE_ATTRIBUTE_NO_SCRUB_DATA(0x00020000);

    private long value;

    FileAttributes(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
