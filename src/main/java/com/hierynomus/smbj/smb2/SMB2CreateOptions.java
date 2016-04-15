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
package com.hierynomus.smbj.smb2;

import com.hierynomus.protocol.commons.EnumWithValue;

/**
 * SMB2 Create 2.2.13 - CreateOptions
 */
public enum SMB2CreateOptions implements EnumWithValue<SMB2CreateOptions> {
    FILE_DIRECTORY_FILE(0x00000001),
    FILE_WRITE_THROUGH(0x00000002),
    FILE_SEQUENTIAL_ONLY(0x00000004),
    FILE_NO_INTERMEDIATE_BUFFERING(0x00000008),
    FILE_SYNCHRONOUS_IO_ALERT(0x00000010),
    FILE_SYNCHRONOUS_IO_NONALERT(0x00000020),
    FILE_NON_DIRECTORY_FILE(0x00000040),
    FILE_COMPLETE_IF_OPLOCKED(0x00000100),
    FILE_NO_EA_KNOWLEDGE(0x00000200),
    FILE_RANDOM_ACCESS(0x00000800),
    FILE_DELETE_ON_CLOSE(0x00001000),
    FILE_OPEN_BY_FILE_ID(0x00002000),
    FILE_OPEN_FOR_BACKUP_INTENT(0x00004000),
    FILE_NO_COMPRESSION(0x00008000),
    FILE_OPEN_REMOTE_INSTANCE(0x00000400),
    FILE_OPEN_REQUIRING_OPLOCK(0x00010000),
    FILE_DISALLOW_EXCLUSIVE(0x00020000),
    FILE_RESERVE_OPFILTER(0x00100000),
    FILE_OPEN_REPARSE_POINT(0x00200000),
    FILE_OPEN_NO_RECALL(0x00400000),
    FILE_OPEN_FOR_FREE_SPACE_QUERY(0x00800000);

    private long value;

    SMB2CreateOptions(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
