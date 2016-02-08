/*
 * Copyright (C)2016 - Jeroen van Erp <jeroen@hierynomus.com>
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
package com.hierynomus.smbj.smb2;

import com.hierynomus.protocol.commons.EnumWithValue;

public enum SMB2MessageFlag implements EnumWithValue<SMB2MessageFlag> {
    SMB2_FLAGS_SERVER_TO_REDIR(0x00000001),
    SMB2_FLAGS_ASYNC_COMMAND(0x00000002),
    SMB2_FLAGS_RELATED_OPERATIONS(0x00000004),
    SMB2_FLAGS_SIGNED(0x00000008),
    SMB2_FLAGS_PRIORITY_MASK(0x00000070),
    SMB2_FLAGS_DFS_OPERATIONS(0x10000000),
    SMB2_FLAGS_REPLAY_OPERATION(0x20000000);

    private long value;

    SMB2MessageFlag(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
