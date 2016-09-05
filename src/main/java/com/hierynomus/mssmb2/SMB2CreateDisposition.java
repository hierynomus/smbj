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
 * [MS-SMB2].pdf 2.2.13 SMB2 CREATE Request - CreateDisposition
 * <p>
 * Defines the action the server MUST take if the file that is specified in the name field already exists.
 * For opening named pipes, this field may be set to any value by the client and MUST be ignored by the server.
 * For other files, this field MUST contain one of the following values.
 */
public enum SMB2CreateDisposition implements EnumWithValue<SMB2CreateDisposition> {
    /** If the file already exists, supersede it. Otherwise, create the file. This value SHOULD NOT be used for a printer object. */
    FILE_SUPERSEDE(0x00000000L),
    /** If the file already exists, return success; otherwise, fail the operation. MUST NOT be used for a printer object. */
    FILE_OPEN(0x00000001L),
    /** If the file already exists, fail the operation; otherwise, create the file. */
    FILE_CREATE(0x00000002L),
    /** Open the file if it already exists; otherwise, create the file. This value SHOULD NOT be used for a printer object. */
    FILE_OPEN_IF(0x00000003L),
    /** Overwrite the file if it already exists; otherwise, fail the operation. MUST NOT be used for a printer object. */
    FILE_OVERWRITE(0x00000004L),
    /** Overwrite the file if it already exists; otherwise, create the file. This value SHOULD NOT be used for a printer object. */
    FILE_OVERWRITE_IF(0x00000005L);

    private long value;

    SMB2CreateDisposition(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
