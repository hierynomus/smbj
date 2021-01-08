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
package com.hierynomus.mssmb2.messages.negotiate;

import com.hierynomus.mssmb2.SMB3EncryptionCipher;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

import java.util.ArrayList;
import java.util.List;

/**
 * [MS-SMB2].pdf 2.2.3.1.2 / 2.2.4.1.2 SMB2_ENCRYPTION_CAPABILITIES Request/Response
 */
public class SMB2EncryptionCapabilities extends SMB2NegotiateContext {
    private List<SMB3EncryptionCipher> cipherList;


    public SMB2EncryptionCapabilities() {
        super(SMB2NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES);
        this.cipherList = new ArrayList<>();
    }

    public SMB2EncryptionCapabilities(List<SMB3EncryptionCipher> cipherList) {
        super(SMB2NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES);
        this.cipherList = cipherList;
    }

    @Override
    protected int writeContext(SMBBuffer buffer) {
        if (cipherList == null || cipherList.isEmpty()) {
            throw new IllegalStateException("Cannot serialize an empty or null cipherList");
        }

        buffer.putUInt16(cipherList.size()); // CipherCount (2 bytes)
        // Ciphers (variable)
        for (SMB3EncryptionCipher encryptionCipher : cipherList) {
            buffer.putUInt16((int) encryptionCipher.getValue()); // Cipher (2 bytes)
        }
        return 2 + 2 * cipherList.size();

    }

    @Override
    protected void readContext(SMBBuffer buffer, int dataSize) throws Buffer.BufferException {
        int cipherCount = buffer.readUInt16(); // CipherCount (2 bytes)
        for (int i = 0; i < cipherCount; i++) {
            cipherList.add(EnumWithValue.EnumUtils.valueOf(buffer.readUInt16(), SMB3EncryptionCipher.class, null)); // Cipher (2 bytes)
        }
    }

    public List<SMB3EncryptionCipher> getCipherList() {
        return cipherList;
    }
}
