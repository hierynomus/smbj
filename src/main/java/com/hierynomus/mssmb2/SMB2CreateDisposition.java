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
 * SMB2 Create 2.2.13 - CreateDisposition
 */
public enum SMB2CreateDisposition implements EnumWithValue<SMB2CreateDisposition> {
    FILE_SUPERSEDE(0x00000000L),
    FILE_OPEN(0x00000001L),
    FILE_CREATE(0x00000002L),
    FILE_OPEN_IF(0x00000003L),
    FILE_OVERWRITE(0x00000004L),
    FILE_OVERWRITE_IF(0x00000005L);

    private long value;

    SMB2CreateDisposition(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
