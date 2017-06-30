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
import com.hierynomus.smbj.common.SMBBuffer;

public class SMB2Error {

    static SMB2Error readFrom(SMBBuffer buffer) throws Buffer.BufferException {
        buffer.skip(2); // StructureSize (2 bytes)
        int errorContextCount = buffer.readByte(); // ErrorContextCount (1 byte)
        buffer.skip(1); // Reserved (1 byte)
        int byteCount = buffer.readUInt32AsInt(); // ByteCount (4 bytes)

        if (byteCount == 0) {
            buffer.skip(1); // ErrorData (1 byte)
        }

        return new SMB2Error();
    }
}
