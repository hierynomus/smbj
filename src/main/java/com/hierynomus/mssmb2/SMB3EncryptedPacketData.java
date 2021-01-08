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
import com.hierynomus.smb.SMBPacketData;

public class SMB3EncryptedPacketData extends SMBPacketData<SMB2TransformHeader> {
    public SMB3EncryptedPacketData(byte[] data) throws Buffer.BufferException {
        super(new SMB2TransformHeader(), data);
    }

    public byte[] getCipherText() throws Buffer.BufferException {
        return getDataBuffer().readRawBytes(getHeader().getOriginalMessageSize());
    }

    @Override
    public String toString() {
        return "Encrypted for session id << " + getHeader().getSessionId() + " >>";
    }

}
