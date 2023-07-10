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
import com.hierynomus.protocol.transport.PacketFactory;

public class SMB2PacketFactory implements PacketFactory<SMB2PacketData> {

    @Override
    public SMB2PacketData read(byte[] data) throws Buffer.BufferException {
        return new SMB2PacketData(data);
    }

    @Override
    public boolean canHandle(byte[] data) {
        return data.length >= 4 && data[0] == (byte) 0xFE && data[1] == 'S' && data[2] == 'M' && data[3] == 'B';
    }
}
