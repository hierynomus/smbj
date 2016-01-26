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

import java.util.EnumSet;

public enum SMB2Dialect {
    UNKNOWN(0x0),
    SMB_2_0_2(0x0202),
    SMB_2_1(0x0210),
    SMB_2XX(0x02FF),
    SMB_3_0(0x0300),
    SMB_3_0_2(0x0302),
    SMB_3_1_1(0x0311);

    private int value;

    SMB2Dialect(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public boolean isSmb3x() {
        return this == SMB_3_0 || this == SMB_3_0_2 || this == SMB_3_1_1;
    }

    /**
     * Whether any of the dialects in the set is an SMB 3.x dialect.
     * @param dialects The supported dialects enumset.
     * @return true if there is (at least) one SMB 3.x dialect in the set.
     */
    public static boolean supportsSmb3x(EnumSet<SMB2Dialect> dialects) {
        for (SMB2Dialect dialect : dialects) {
            if (dialect.isSmb3x()) {
                return true;
            }
        }
        return false;
    }

    public static SMB2Dialect lookup(int v) {
        for (SMB2Dialect smb2Dialect : values()) {
            if (smb2Dialect.getValue() == v) {
                return smb2Dialect;
            }
        }
        throw new IllegalStateException("Unknown SMB2 Dialect: " + v);
    }
}
