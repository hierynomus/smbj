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
 * [MS-SMB2].pdf 2.2.14 SMB2 CREATE Response- CreateAction
 * <p>
 *  The action taken in establishing the open. This field MUST contain one of
 *  the following values.
 */
public enum SMB2CreateAction implements EnumWithValue<SMB2CreateAction> {

    /**
     * An existing file was deleted and a new file was created in its place.
     */
    FILE_SUPERSEDED(0x00000000L),
    /**
     * An existing file was opened.
     */
    FILE_OPENED(0x00000001L),
    /**
     * A new file was created.
     */
    FILE_CREATED(0x00000002L),
    /**
     * An existing file was overwritten
     */
    FILE_OVERWRITTEN(0x00000003L);

    private long value;

    SMB2CreateAction(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
