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
package com.hierynomus.smbj.io;

import java.io.IOException;

public class ArrayByteChunkProvider extends ByteChunkProvider {

    private final byte[] data;
    private int bufferOffset;
    private int remaining;

    public ArrayByteChunkProvider(byte[] data, long fileOffset) {
        this(data, 0, data.length, fileOffset);
    }

    public ArrayByteChunkProvider(byte[] data, int offset, int length, long fileOffset) {
        this.data = data;
        this.offset = fileOffset;
        this.bufferOffset = offset;
        this.remaining = length;
    }

    @Override
    public boolean isAvailable() {
        return remaining > 0;
    }

    @Override
    protected int getChunk(byte[] chunk) throws IOException {
        int write = chunk.length;
        if (write > remaining) {
            write = remaining;
        }
        System.arraycopy(data, bufferOffset, chunk, 0, write);
        bufferOffset += write;
        remaining -= write;

        return write;
    }

    @Override
    public int bytesLeft() {
        return remaining;
    }
}
