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
import com.hierynomus.protocol.transport.PacketFactory;

import java.io.IOException;

public class SMB1MessageConverter implements PacketFactory<SMB1Packet> {
    @Override
    public SMB1Packet read(byte[] data) throws Buffer.BufferException, IOException {
        throw new SMB1NotSupportedException();
    }

    @Override
    public boolean canHandle(byte[] data) {
        return data[0] == (byte) 0xFF && data[1] == 'S' && data[2] == 'M' && data[3] == 'B';
    }
}
