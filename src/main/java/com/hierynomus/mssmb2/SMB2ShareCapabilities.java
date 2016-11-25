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
 * [MS-SMB2].pdf 2.2.10 TREE_CONNECT Response Capabilities
 */
public enum SMB2ShareCapabilities implements EnumWithValue<SMB2ShareCapabilities> {
    SMB2_SHARE_CAP_DFS(0x08L),
    SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY(0x10L),
    SMB2_SHARE_CAP_SCALEOUT(0x20L),
    SMB2_SHARE_CAP_CLUSTER(0x40L),
    SMB2_SHARE_CAP_ASYMMETRIC(0x80L);

    private long value;

    SMB2ShareCapabilities(long value) {
        this.value = value;
    }

    @Override
    public long getValue() {
        return value;
    }
}
