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
 * [MS-SMB2].pdf 2.2.13 SMB2 CREATE Request - OplockLevel
 * <p>
 */
public enum SMB2OplockLevel implements EnumWithValue<SMB2OplockLevel> {
    SMB2_OPLOCK_LEVEL_NONE(0x00L),
    SMB2_OPLOCK_LEVEL_II(0x01L),
    SMB2_OPLOCK_LEVEL_EXCLUSIVE(0x08L),
    SMB2_OPLOCK_LEVEL_BATCH(0x09L),
    // TODO: implement and support using lease
    OPLOCK_LEVEL_LEASE(0xFFL);

    private long value;

    SMB2OplockLevel(long value) {
        this.value = value;
    }

    @Override
    public long getValue() {
        return value;
    }
}
