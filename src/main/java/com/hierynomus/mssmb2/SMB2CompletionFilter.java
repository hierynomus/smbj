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
package com.hierynomus.mssmb2;

import com.hierynomus.protocol.commons.EnumWithValue;

/**
 * SMB2 Change Notify 2.2.35 - CompletionFilter
 */
public enum SMB2CompletionFilter implements EnumWithValue<SMB2CompletionFilter> {
    FILE_NOTIFY_CHANGE_FILE_NAME(0x00000001L),
    FILE_NOTIFY_CHANGE_DIR_NAME(0x00000002L),
    FILE_NOTIFY_CHANGE_ATTRIBUTES(0x00000004L),
    FILE_NOTIFY_CHANGE_SIZE(0x00000008L),
    FILE_NOTIFY_CHANGE_LAST_WRITE(0x00000010L),
    FILE_NOTIFY_CHANGE_LAST_ACCESS(0x00000020L),
    FILE_NOTIFY_CHANGE_CREATION(0x00000040L),
    FILE_NOTIFY_CHANGE_EA(0x00000080L),
    FILE_NOTIFY_CHANGE_SECURITY(0x00000100L),
    FILE_NOTIFY_CHANGE_STREAM_NAME(0x00000200L),
    FILE_NOTIFY_CHANGE_STREAM_SIZE(0x00000400L),
    FILE_NOTIFY_CHANGE_STREAM_WRITE(0x00000800L);

    private long value;

    SMB2CompletionFilter(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
