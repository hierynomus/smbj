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

import com.hierynomus.mssmb2.Smb2EncryptionCipher;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

/***
 * [MS-SMB2].pdf 2.2.4.1.2 SMB2_ENCRYPTION_CAPABILITIES Response
 */
public class SMB2EncryptionCapabilitiesResponse extends SMB2NegotiateContext {

    // the CipherCount is always 1 for response.
    private Smb2EncryptionCipher cipher;

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        buffer.readUInt16(); // CipherCount (2 bytes), should always is 1.
        cipher = EnumWithValue.EnumUtils.valueOf(buffer.readUInt16(), Smb2EncryptionCipher.class, null); // Ciphers (2 bytes)
    }

    public Smb2EncryptionCipher getEncryptionCipher() {
        return cipher;
    }

}
