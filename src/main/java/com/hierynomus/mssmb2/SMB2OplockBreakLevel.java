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
 * [MS-SMB2].pdf 2.2.23 SMB2 OPLOCK_BREAK Notification - OplockLevel
 */
public enum SMB2OplockBreakLevel implements EnumWithValue<SMB2OplockBreakLevel> {
    SMB2_OPLOCK_LEVEL_NONE(0x00L),
    SMB2_OPLOCK_LEVEL_II(0x01L);

    private long value;

    SMB2OplockBreakLevel(long value) {
        this.value = value;
    }

    @Override
    public long getValue() {
        return value;
    }
}
