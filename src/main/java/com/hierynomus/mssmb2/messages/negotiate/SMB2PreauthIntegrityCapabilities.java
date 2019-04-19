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

import com.hierynomus.mssmb2.SMB3HashAlgorithm;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

import java.util.ArrayList;
import java.util.List;

/**
 * [MS-SMB2].pdf 2.2.3.1.1 / 2.2.4.1.1 SMB2_PREAUTH_INTEGRITY_CAPABILITIES Request/Response
 */
public class SMB2PreauthIntegrityCapabilities extends SMB2NegotiateContext {
    // [MS-SMB2].pdf <103> Section 3.2.4.2.2.2: Windows 10, Windows Server 2016, and Windows Server operating
    // system use 32 bytes of Salt.
    public static final int DEFAULT_SALT_LENGTH = 32;
    private List<SMB3HashAlgorithm> hashAlgorithms;
    private byte[] salt;

    public SMB2PreauthIntegrityCapabilities() {
        super(SMB2NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES);
        this.hashAlgorithms = new ArrayList<>();
    }

    public SMB2PreauthIntegrityCapabilities(List<SMB3HashAlgorithm> hashAlgorithms, byte[] salt) {
        super(SMB2NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES);
        this.hashAlgorithms = hashAlgorithms;
        this.salt = salt.clone();
    }

    @Override
    protected int writeContext(SMBBuffer buffer) {
        if (hashAlgorithms == null) {
            throw new IllegalStateException("There should be at least 1 hash algorithm provided");
        }
        if (salt == null) {
            throw new IllegalStateException("A salt should be provided");
        }
        buffer.putUInt16(hashAlgorithms.size()); // HashAlgorithmCount (2 bytes)
        buffer.putUInt16(salt.length); // SaltLength (2 bytes)
        for (SMB3HashAlgorithm hashAlgorithm : hashAlgorithms) {
            buffer.putUInt16((int) hashAlgorithm.getValue()); // HashAlgorithm (2 bytes)
        }
        buffer.putRawBytes(salt); // Salt (variable)

        return 4 + 2 * hashAlgorithms.size() + salt.length;
    }

    @Override
    protected void readContext(SMBBuffer buffer, int dataSize) throws Buffer.BufferException {
        int hashAlgorithmCount = buffer.readUInt16(); // HashAlgorithmCount (2 bytes)
        int saltLength = buffer.readUInt16(); // SaltLength (2 bytes)
        for (int i = 0; i < hashAlgorithmCount; i++) {
            hashAlgorithms.add(EnumWithValue.EnumUtils.valueOf(buffer.readUInt16(), SMB3HashAlgorithm.class, null)); // HashAlgorithm (2 bytes)
        }
        this.salt = buffer.readRawBytes(saltLength); // Salt (variable)
    }

    public byte[] getSalt() {
        return salt;
    }

    public List<SMB3HashAlgorithm> getHashAlgorithms() {
        return hashAlgorithms;
    }
}
