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
package com.hierynomus.smb;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBRuntimeException;

public class Packets {
    /**
     * Get the serialized packet bytes.
     * @param packet
     * @return
     * @throws Buffer.BufferException
     */
    public static byte[] getPacketBytes(SMBPacket<?, ?> packet) {
        SMBBuffer buffer = packet.getBuffer();
        int originalPos = buffer.rpos();
        buffer.rpos(packet.getHeader().getHeaderStartPosition());
        byte[] packetBytes = new byte[packet.getHeader().getMessageEndPosition() - packet.getHeader().getHeaderStartPosition()]; // Allocate large enough byte[] for message
        try {
            buffer.readRawBytes(packetBytes);
        } catch (Buffer.BufferException be) {
            throw new SMBRuntimeException("Cannot read packet bytes from buffer", be);
        }
        buffer.rpos(originalPos);
        return packetBytes;
    }


}
