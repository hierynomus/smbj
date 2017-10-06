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
 * [MS-FSCC].pdf 2.4.42 File Notify Information Action
 */
public enum FileNotifyAction implements EnumWithValue<FileNotifyAction> {
    FILE_ACTION_ADDED(0x00000001L),
    FILE_ACTION_REMOVED(0x00000002L),
    FILE_ACTION_MODIFIED(0x00000003L),
    FILE_ACTION_RENAMED_OLD_NAME(0x00000004L),
    FILE_ACTION_RENAMED_NEW_NAME(0x00000005L),
    FILE_ACTION_ADDED_STREAM(0x00000006L),
    FILE_ACTION_REMOVED_STREAM(0x00000007L),
    FILE_ACTION_MODIFIED_STREAM(0x00000008L),
    FILE_ACTION_REMOVED_BY_DELETE(0x00000009L),
    FILE_ACTION_ID_NOT_TUNNELLED(0x0000000AL),
    FILE_ACTION_TUNNELLED_ID_COLLISION(0x0000000BL);

    private long value;

    FileNotifyAction(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
