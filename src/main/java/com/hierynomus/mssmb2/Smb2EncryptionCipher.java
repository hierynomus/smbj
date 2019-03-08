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

/***
 * [MS-SMB2].pdf 2.2.3.1.2 SMB2_ENCRYPTION_CAPABILITIES -- Cipher
 */
public enum Smb2EncryptionCipher implements EnumWithValue<Smb2EncryptionCipher> {
    AES_128_CCM(0x00000001L),
    AES_128_GCM(0x00000002L);

    private long value;

    Smb2EncryptionCipher(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }

    public String getAlgorithmName() {
        switch (this) {
            case AES_128_CCM:
                return "AES/CCM/NoPadding";
            case AES_128_GCM:
                return "AES/GCM/NoPadding";
            default:
                return "";
        }
    }
}
