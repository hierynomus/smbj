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
 * [MS-SMB2].pdf 2.2.3 SMB2 NEGOTIATE Request - Capabilities
 */
public enum SMB2GlobalCapability implements EnumWithValue<SMB2GlobalCapability> {
    SMB2_GLOBAL_CAP_DFS(0x01L),
    SMB2_GLOBAL_CAP_LEASING(0x02L),
    SMB2_GLOBAL_CAP_LARGE_MTU(0x04L), // Multi-Credit support
    SMB2_GLOBAL_CAP_MULTI_CHANNEL(0x08L),
    SMB2_GLOBAL_CAP_PERSISTENT_HANDLES(0x10L),
    SMB2_GLOBAL_CAP_DIRECTORY_LEASING(0x20L),
    SMB2_GLOBAL_CAP_ENCRYPTION(0x40L);

    private long i;

    SMB2GlobalCapability(long i) {
        this.i = i;
    }

    public long getValue() {
        return i;
    }
}
