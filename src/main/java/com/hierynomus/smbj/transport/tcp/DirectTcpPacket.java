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
package com.hierynomus.smbj.transport.tcp;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.smbj.common.SMBBuffer;

public class DirectTcpPacket extends Buffer<DirectTcpPacket> {

    public DirectTcpPacket(SMBBuffer from) {
        super(from.available() + 4, Endian.BE);
        // First 0 byte
        putByte((byte) 0);
        // 3 bytes length of message
        int length = from.available();
        putUInt24(length);
        // Original SMB message
        putBuffer(from);
    }
}
