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
package com.hierynomus.mssmb2.messages.submodule;

import com.hierynomus.mssmb2.SMB2NegotiateContextType;
import com.hierynomus.mssmb2.Smb2HashAlgorithm;
import com.hierynomus.smb.SMBBuffer;

import java.util.List;

/***
 * [MS-SMB2].pdf 2.2.3.1.1 SMB2_PREAUTH_INTEGRITY_CAPABILITIES Request
 */
public class SMB2PreauthIntegrityCapabilitiesRequest extends SMB2NegotiateContext {

    // HashAlgorithmCount (2 bytes) + SaltLength (2 bytes) is always 4 bytes
    private static final int FIXED_PART_SIZE = 4;
    // [MS-SMB2].pdf <103> Section 3.2.4.2.2.2: Windows 10, Windows Server 2016, and Windows Server operating
    // system use 32 bytes of Salt.
    public static final int DEFAULT_SALT_LENGTH = 32;
    private List<Smb2HashAlgorithm> hashAlgorithmList;
    private byte[] salt;

    public SMB2PreauthIntegrityCapabilitiesRequest(List<Smb2HashAlgorithm> hashAlgorithmList, byte[] salt) {
        super(SMB2NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES, FIXED_PART_SIZE + 2 * hashAlgorithmList.size() + salt.length);
        this.hashAlgorithmList = hashAlgorithmList;
        this.salt = salt.clone();
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        if (hashAlgorithmList != null && salt != null) {
            buffer.putUInt16(hashAlgorithmList.size()); // HashAlgorithmCount (2 bytes)
            buffer.putUInt16(salt.length); // SaltLength (2 bytes)
            // HashAlgorithms (variable)
            for (Smb2HashAlgorithm hashAlgorithm: hashAlgorithmList) {
                buffer.putUInt16((int) hashAlgorithm.getValue()); // 16-bit integer IDs
            }
            buffer.putRawBytes(salt); // Salt (variable)
        } else {
            // FIXME log the error state
        }
    }

}
