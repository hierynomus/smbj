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
package com.hierynomus.msdtyp.ace;

import com.hierynomus.protocol.commons.EnumWithValue;

public enum AceFlag implements EnumWithValue<AceFlag> {
    CONTAINER_INHERIT_ACE(0x02L),
    FAILED_ACCESS_ACE_FLAG(0x80L),
    INHERIT_ONLY_ACE(0x08L),
    INHERITED_ACE(0x10L),
    NO_PROPAGATE_INHERIT_ACE(0x04L),
    OBJECT_INHERIT_ACE(0x01L),
    SUCCESSFUL_ACCESS_ACE_FLAG(0x40L);

    private long value;

    AceFlag(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
