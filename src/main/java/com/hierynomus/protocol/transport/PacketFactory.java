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
package com.hierynomus.protocol.transport;

import com.hierynomus.protocol.Packet;
import com.hierynomus.protocol.commons.buffer.Buffer;

import java.io.IOException;

public interface PacketFactory<P extends Packet<?>> {

    /**
     * Construct a packet out of the raw byte data.
     *
     * @param data the byte array containing the full packet data
     * @return A newly constructed packet.
     */
    P read(byte[] data) throws Buffer.BufferException, IOException;

    /**
     * Checks whether this PacketFactory is able to handle the incoming raw byte data.
     *
     * @param data the byte array containing the full packet data
     * @return true if the {@link #read(byte[])} will result in a packet, false otherwise.
     */
    boolean canHandle(byte[] data);
}
