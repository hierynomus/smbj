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
 * SMB2 lease state bitmask ([MS-SMB2] 2.2.13.2.8 LeaseState). A directory lease is
 * granted at most {@code RH} (the server strips WRITE_CACHING for directories).
 */
public enum SMB2LeaseState implements EnumWithValue<SMB2LeaseState> {
    SMB2_LEASE_NONE(0x00L),
    SMB2_LEASE_READ_CACHING(0x01L),
    SMB2_LEASE_HANDLE_CACHING(0x02L),
    SMB2_LEASE_WRITE_CACHING(0x04L);

    private final long value;

    SMB2LeaseState(long value) {
        this.value = value;
    }

    @Override
    public long getValue() {
        return value;
    }

    public static boolean isRead(long state) {
        return (state & SMB2_LEASE_READ_CACHING.value) != 0;
    }

    public static boolean isHandle(long state) {
        return (state & SMB2_LEASE_HANDLE_CACHING.value) != 0;
    }

    public static boolean isWrite(long state) {
        return (state & SMB2_LEASE_WRITE_CACHING.value) != 0;
    }

    /** Read+Handle caching (0x3) — the useful directory lease. */
    public static boolean isReadHandle(long state) {
        return isRead(state) && isHandle(state);
    }

    /** The RH bitmask value (0x3). */
    public static long readHandle() {
        return SMB2_LEASE_READ_CACHING.value | SMB2_LEASE_HANDLE_CACHING.value;
    }
}
