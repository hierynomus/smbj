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

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

/**
 * PacketData class that indicates this PacketData was instantiated in the PacketEncryptor as part of the
 * decryption.
 */
public class SMB2DecryptedPacketData extends SMB2PacketData {
    public SMB2DecryptedPacketData(byte[] data) throws Buffer.BufferException {
        super(data);
    }

    public SMB2DecryptedPacketData(SMBBuffer dataBuffer) throws Buffer.BufferException {
        super(dataBuffer);
    }


    public SMB2PacketData next() throws Buffer.BufferException {
        if (isCompounded()) {
            return new SMB2DecryptedPacketData(dataBuffer);
        } else {
            return null;
        }
    }

    public boolean isDecrypted() {
        return true;
    }
}
