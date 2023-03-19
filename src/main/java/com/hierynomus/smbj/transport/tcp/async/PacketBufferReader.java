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
package com.hierynomus.smbj.transport.tcp.async;

import com.hierynomus.protocol.Packet;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PacketBufferReader {
    private static final int NO_PACKET_LENGTH = -1;
    private static final int HEADER_SIZE = 4;
    private static final int READ_BUFFER_CAPACITY = 9000; // Size of a Jumbo frame

    private final ByteBuffer readBuffer;
    private byte[] currentPacketBytes;
    private int currentPacketLength = NO_PACKET_LENGTH;
    private int currentPacketOffset = 0;

    public <P extends Packet<?>> PacketBufferReader() {
        this.readBuffer = ByteBuffer.allocate(READ_BUFFER_CAPACITY);
        this.readBuffer.order(ByteOrder.BIG_ENDIAN);
    }


    public byte[] readNext() {
        ((java.nio.Buffer) readBuffer).flip(); // prepare to process received data (cast is to avoid Java 8/9 compatibility issues)
        byte[] bytes = null;
        if (isAwaitingHeader() && isHeaderAvailable()) {
            currentPacketLength = readPacketHeader();
            currentPacketBytes = new byte[currentPacketLength];
            bytes = readPacketBody();
        } else if (!isAwaitingHeader()) {
            bytes = readPacketBody();
        }
        readBuffer.compact(); // prepare to receive more data
        if (bytes != null) {
            currentPacketBytes = null;
            currentPacketOffset = 0;
            currentPacketLength = NO_PACKET_LENGTH;
        }
        return bytes;
    }

    private int readPacketHeader() {
        return readBuffer.getInt() & 0xffffff;
    }

    private boolean isHeaderAvailable() {
        return readBuffer.remaining() >= HEADER_SIZE;
    }

    public ByteBuffer getBuffer() {
        return readBuffer;
    }

    private boolean isAwaitingHeader() {
        return currentPacketLength == NO_PACKET_LENGTH;
    }

    private byte[] readPacketBody() {
        int length = currentPacketLength - currentPacketOffset;
        if (length > readBuffer.remaining()) {
            length = readBuffer.remaining();
        }
        readBuffer.get(currentPacketBytes, currentPacketOffset, length);
        currentPacketOffset += length;

        if (currentPacketOffset == currentPacketLength) {
            return currentPacketBytes;
        }
        return null;
    }
}
