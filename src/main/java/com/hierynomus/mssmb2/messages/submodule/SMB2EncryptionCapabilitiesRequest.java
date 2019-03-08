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
import com.hierynomus.mssmb2.Smb2EncryptionCipher;
import com.hierynomus.smb.SMBBuffer;

import java.util.List;

/***
 * [MS-SMB2].pdf 2.2.3.1.2 SMB2_ENCRYPTION_CAPABILITIES Request
 */
public class SMB2EncryptionCapabilitiesRequest extends SMB2NegotiateContext {

    // CipherCount is always 2 bytes
    private static final int FIXED_CIPHER_COUNT_SIZE = 2;
    private List<Smb2EncryptionCipher> cipherList;

    public SMB2EncryptionCapabilitiesRequest(List<Smb2EncryptionCipher> cipherList) {
        super(SMB2NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES, FIXED_CIPHER_COUNT_SIZE +  2 * cipherList.size());
        this.cipherList = cipherList;
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        if (cipherList != null) {
            buffer.putUInt16(cipherList.size()); // CipherCount (2 bytes)
            // Ciphers (variable)
            for (Smb2EncryptionCipher encryptionCipher: cipherList) {
                buffer.putUInt16((int) encryptionCipher.getValue()); // 16-bit integer IDs
            }
        } else {
            // FIXME log the error state
        }
    }
}
