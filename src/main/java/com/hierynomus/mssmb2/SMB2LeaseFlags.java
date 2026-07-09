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
 * SMB2 lease flags ([MS-SMB2] 2.2.13.2.8 / 2.2.13.2.10). {@code PARENT_LEASE_KEY_SET}
 * is set on a V2 request/response when ParentLeaseKey carries the enclosing directory's
 * lease key; {@code BREAK_IN_PROGRESS} appears only in responses.
 */
public enum SMB2LeaseFlags implements EnumWithValue<SMB2LeaseFlags> {
    SMB2_LEASE_FLAG_NONE(0x00L),
    SMB2_LEASE_FLAG_BREAK_IN_PROGRESS(0x02L),
    SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET(0x04L);

    private final long value;

    SMB2LeaseFlags(long value) {
        this.value = value;
    }

    @Override
    public long getValue() {
        return value;
    }
}
