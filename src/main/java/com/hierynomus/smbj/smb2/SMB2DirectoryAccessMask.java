/*
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
package com.hierynomus.smbj.smb2;

import com.hierynomus.protocol.commons.EnumWithValue;

/**
 * SMB2 Create 2.2.13 - SMB2ShareAccess
 */
public enum SMB2DirectoryAccessMask implements EnumWithValue<SMB2DirectoryAccessMask> {
    FILE_LIST_DIRECTORY(0x00000001),
    FILE_ADD_FILE(0x00000002),
    FILE_ADD_SUBDIRECTORY(0x00000004),
    FILE_READ_EA(0x00000008),
    FILE_WRITE_EA(0x00000010),
    FILE_TRAVERSE(0x00000020),
    FILE_DELETE_CHILD(0x00000040),
    FILE_READ_ATTRIBUTES(0x00000080),
    FILE_WRITE_ATTRIBUTES(0x00000100),
    DELETE(0x00010000),
    READ_CONTROL(0x00020000),
    WRITE_DAC(0x00040000),
    WRITE_OWNER(0x00080000),
    SYNCHRONIZE(0x00100000),
    ACCESS_SYSTEM_SECURITY(0x01000000),
    MAXIMUM_ALLOWED(0x02000000),
    GENERIC_ALL(0x10000000),
    GENERIC_EXECUTE(0x20000000),
    GENERIC_WRITE(0x40000000),
    GENERIC_READ(0x80000000);


    private long value;

    SMB2DirectoryAccessMask(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
