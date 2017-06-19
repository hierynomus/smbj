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

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * SMB2 Create 2.2.13 - SMB2ShareAccess
 */
public enum SMB2ShareAccess implements EnumWithValue<SMB2ShareAccess> {
    FILE_SHARE_READ(0x00000001L),
    FILE_SHARE_WRITE(0x00000002L),
    FILE_SHARE_DELETE(0x00000004L);

    public static final Set<SMB2ShareAccess> ALL = Collections.unmodifiableSet(EnumSet.allOf(SMB2ShareAccess.class));

    private long value;

    SMB2ShareAccess(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
