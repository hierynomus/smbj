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
 * [MS-SMB2].pdf 2.2.26.1 SMB2_LOCK_ELEMENT Structure - Flags
 */
public enum SMB2LockFlag implements EnumWithValue<SMB2LockFlag> {
    SMB2_LOCKFLAG_SHARED_LOCK(0x01L),
    SMB2_LOCKFLAG_EXCLUSIVE_LOCK(0x02L),
    SMB2_LOCKFLAG_UNLOCK(0x04L),
    SMB2_LOCKFLAG_FAIL_IMMEDIATELY(0x10L);

    private long value;

    SMB2LockFlag(long value) {
        this.value = value;
    }

    @Override
    public long getValue() {
        return value;
    }
}
