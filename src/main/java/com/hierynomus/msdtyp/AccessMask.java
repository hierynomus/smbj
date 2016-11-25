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
package com.hierynomus.msdtyp;

import com.hierynomus.protocol.commons.EnumWithValue;

/**
 * MS-DTYP 2.4.3 ACCESS_MASK
 * <p>
 * Its ok to find multiple names pointing to the same values, Since the
 * same access mask when applied to File, Folder or other object are just
 * named/called differently.
 */
public enum AccessMask implements EnumWithValue<AccessMask> {

    // 2.2.13.1.1 File_Pipe_Printer_Access_Mask
    FILE_READ_DATA(0x00000001L),
    FILE_WRITE_DATA(0x00000002L),
    FILE_APPEND_DATA(0x00000004L),

    // 2.2.13.1.2 Directory_Access_Mask
    FILE_LIST_DIRECTORY(0x00000001L),
    FILE_ADD_FILE(0x00000002L),
    FILE_ADD_SUBDIRECTORY(0x00000004L),
    FILE_TRAVERSE(0x00000020L),
    FILE_DELETE_CHILD(0x00000040L),
    FILE_READ_ATTRIBUTES(0x00000080L),
    FILE_WRITE_ATTRIBUTES(0x00000100L),

    // Common for Both
    FILE_READ_EA(0x00000008L),
    FILE_WRITE_EA(0x00000010L),
    DELETE(0x00010000L),
    READ_CONTROL(0x00020000L),
    WRITE_DAC(0x00040000L),
    WRITE_OWNER(0x00080000L),
    SYNCHRONIZE(0x00100000L),
    ACCESS_SYSTEM_SECURITY(0x01000000L),
    MAXIMUM_ALLOWED(0x02000000L),
    GENERIC_ALL(0x10000000L),
    GENERIC_EXECUTE(0x20000000L),
    GENERIC_WRITE(0x40000000L),
    GENERIC_READ(0x80000000L),

    // Object Access Mask
    ADS_RIGHT_DS_CONTROL_ACCESS(0X00000100L),
    ADS_RIGHT_DS_CREATE_CHILD(0X00000001L),
    ADS_RIGHT_DS_DELETE_CHILD(0X00000002L),
    ADS_RIGHT_DS_READ_PROP(0x00000010L),
    ADS_RIGHT_DS_WRITE_PROP(0x00000020L),
    ADS_RIGHT_DS_SELF(0x00000008L);


    private long value;

    AccessMask(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
