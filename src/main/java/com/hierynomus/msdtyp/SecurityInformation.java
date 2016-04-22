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
package com.hierynomus.msdtyp;

import com.hierynomus.protocol.commons.EnumWithValue;

/**
 * [MS-DTYP].pdf 2.4.7 Security Information
 */
public enum SecurityInformation implements EnumWithValue<SecurityInformation> {
    OWNER_SECURITY_INFORMATION(0x00000001L),
    GROUP_SECURITY_INFORMATION(0x00000002L),
    DACL_SECURITY_INFORMATION(0x00000004L),
    SACL_SECURITY_INFORMATION(0x00000008L),
    LABEL_SECURITY_INFORMATION(0x00000010L),
    UNPROTECTED_SACL_SECURITY_INFORMATION(0x10000000L),
    UNPROTECTED_DACL_SECURITY_INFORMATION(0x20000000L),
    PROTECTED_SACL_SECURITY_INFORMATION(0x40000000L),
    PROTECTED_DACL_SECURITY_INFORMATION(0x80000000L),
    ATTRIBUTE_SECURITY_INFORMATION(0x00000020L),
    SCOPE_SECURITY_INFORMATION(0x00000040L),
    BACKUP_SECURITY_INFORMATION(0x00010000L);

    private long value;

    SecurityInformation(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
