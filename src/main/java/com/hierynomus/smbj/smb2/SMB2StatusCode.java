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

/**
 * [MS-ERREF].pdf 2.3.1 NTSTATUS values
 *
 * Subset of the possible values which are useful for SMB2 communication
 */
public enum SMB2StatusCode implements EnumWithValue<SMB2StatusCode> {
    STATUS_SUCCESS(0x00000000L),
    STATUS_BUFFER_OVERFLOW(0x80000005L),
    STATUS_INVALID_PARAMETER(0xc000000DL),
    STATUS_MORE_PROCESSING_REQUIRED(0xc0000016L),
    STATUS_REQUEST_NOT_ACCEPTED(0xc00000D0L),
    STATUS_LOGON_FAILURE(0xc000006dL),
    STATUS_PASSWORD_EXPIRED(0xc0000071L),
    STATUS_INSUFFICIENT_RESOURCES(0xc000009aL),
    STATUS_NOT_SUPPORTED(0xc00000bbL),
    STATUS_USER_SESSION_DELETED(0xc0000203L),
    UNKNOWN(0xffffffffL);

    private long value;

    SMB2StatusCode(long val) {
        value = val;
    }

    @Override
    public long getValue() {
        return value;
    }
}
