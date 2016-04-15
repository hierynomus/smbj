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

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;

/**
 * [MS-SMB2].pdf 2.2.14.1 SMB2_FILEID
 */
public class SMB2FileId {

    private byte[] persistentHandle = new byte[8];

    private byte[] volatileHandle = new byte[8];

    public SMB2FileId(byte[] persistentHandle, byte[] volatileHandle) {
        System.arraycopy(persistentHandle, 0, this.persistentHandle, 0, 8);
        System.arraycopy(volatileHandle, 0, this.volatileHandle, 0, 8);
    }

    public byte[] getPersistentHandle() {
        return persistentHandle;
    }

    public byte[] getVolatileHandle() {
        return volatileHandle;
    }

    public void write(SMBBuffer buffer) {
        buffer.putRawBytes(persistentHandle);
        buffer.putRawBytes(volatileHandle);
    }

    public static SMB2FileId read(SMBBuffer buffer) throws Buffer.BufferException {
        return new SMB2FileId(buffer.readRawBytes(8),buffer.readRawBytes(8));
    }

}
