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

import com.hierynomus.protocol.commons.ByteArrayUtils;
import com.hierynomus.protocol.commons.Objects;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

import java.util.Arrays;

/**
 * [MS-SMB2].pdf 2.2.14.1 SMB2_FILEID
 */
public class SMB2FileId {

    private byte[] persistentHandle;

    private byte[] volatileHandle;

    public SMB2FileId() {
        this.persistentHandle = new byte[]{(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        this.volatileHandle = new byte[]{(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
    }

    public SMB2FileId(byte[] persistentHandle, byte[] volatileHandle) {
        this.persistentHandle = persistentHandle;
        this.volatileHandle = volatileHandle;
    }

    public void write(SMBBuffer buffer) {
        buffer.putRawBytes(persistentHandle);
        buffer.putRawBytes(volatileHandle);
    }

    public static SMB2FileId read(SMBBuffer buffer) throws Buffer.BufferException {
        return new SMB2FileId(buffer.readRawBytes(8), buffer.readRawBytes(8));
    }

    @Override
    public String toString() {
        return "SMB2FileId{" +
            "persistentHandle=" + ByteArrayUtils.printHex(persistentHandle) +
            '}';
    }

    public String toHexString() {
        return ByteArrayUtils.toHex(persistentHandle) + ByteArrayUtils.toHex(volatileHandle);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SMB2FileId smb2FileId = (SMB2FileId) o;
        return Objects.equals(persistentHandle, smb2FileId.persistentHandle) &&
               Objects.equals(volatileHandle, smb2FileId.volatileHandle);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(persistentHandle);
        result = 31 * result + Arrays.hashCode(volatileHandle);
        return result;
    }
}
