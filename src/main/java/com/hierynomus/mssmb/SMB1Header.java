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
package com.hierynomus.mssmb;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smb.SMBHeader;

/**
 * MS-CIFS 2.2.3.1 SMBv1 Message Header.
 *
 * This class is currently hardcoded to SMB_COM_NEGOTIATE
 */
public class SMB1Header implements SMBHeader {
    @Override
    public void writeTo(SMBBuffer buffer) {
        buffer.putRawBytes(new byte[] {(byte) 0xFF, 'S', 'M', 'B'}); // Protocol (4 bytes)
        buffer.putByte((byte) 0x72); // Command (1 byte)
        buffer.putUInt32(0x0); // Status (4 bytes)
        buffer.putByte((byte) 0x18); // Flags (1 byte)
        buffer.putUInt16(0b1100100001010011); // Flags2 (2 bytes)
        buffer.putUInt16(0x0); // PIDHigh (2 bytes)
        buffer.putUInt64(0x0); // SecurityFeatures (8 bytes)
        buffer.putReserved2(); // Reserved (2 bytes)
        buffer.putUInt16(0x0); // TID (2 bytes)
        buffer.putUInt16(0x0); // PIDLow (2 bytes)
        buffer.putUInt16(0x0); // UID (2 bytes)
        buffer.putUInt16(0x0); // MID (2 bytes)
    }

    @Override
    public void readFrom(Buffer<?> buffer) throws Buffer.BufferException {
        throw new UnsupportedOperationException("Receiving SMBv1 Messages not supported in SMBJ");
    }
}
