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
package com.hierynomus.mssmb.messages;

import com.hierynomus.mssmb.SMB1Packet;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * MS-CIFS 2.2.4.52.1 SMB_COM_NEGOTIATE
 */
public class SMB1ComNegotiateRequest extends SMB1Packet {
    private Set<SMB2Dialect> dialects;

    public SMB1ComNegotiateRequest(Set<SMB2Dialect> dialects) {
        this.dialects = dialects;
    }

    @Override
    public void writeTo(SMBBuffer buffer) {
        // SMB_Parameters
        buffer.putByte((byte) 0x0); // WordCount (1 byte)
        // SMB_Data
        List<String> dialectsToWrite = new ArrayList<>();

        // MS-SMB2 3.2.4.2.2.1 Multi-Protocol Negotiate
        dialectsToWrite.add("SMB 2.002");
        if (dialects.size() > 1 || !dialects.contains(SMB2Dialect.SMB_2_0_2)) {
            dialectsToWrite.add("SMB 2.???");
        }

        int byteCount = 0;
        for (String s : dialectsToWrite) {
            byteCount += 1 + (s.length() + 1);
        }

        buffer.putUInt16(byteCount); // ByteCount (2 bytes)
        for (String s : dialectsToWrite) {
            buffer.putByte((byte) 0x02); // BufferFormat (1 byte)
            buffer.putNullTerminatedString(s, StandardCharsets.UTF_8);
        }
    }

    @Override
    public void read(SMBBuffer buffer) throws Buffer.BufferException {
        throw new IllegalStateException("SMBv1 not implemented in SMBJ");
    }

    @Override
    public String toString() {
        return "SMB_COM_NEGOTIATE";
    }
}
