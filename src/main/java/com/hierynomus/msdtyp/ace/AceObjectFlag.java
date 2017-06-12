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

public enum AceObjectFlag implements EnumWithValue<AceObjectFlag> {

    NONE(0x00000000L),
    ACE_OBJECT_TYPE_PRESENT(0x00000001L),
    ACE_INHERITED_OBJECT_TYPE_PRESENT(0x00000002L);

    private long value;

    AceObjectFlag(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
