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
import java.nio.ByteBuffer;

public class ByteBufferByteChunkProvider extends CachingByteChunkProvider {
    private final ByteBuffer buffer;

    public ByteBufferByteChunkProvider(ByteBuffer buffer) {
        super();
        this.buffer = buffer;
    }

    public ByteBufferByteChunkProvider(ByteBuffer buffer, long fileOffset) {
        super();
        this.buffer = buffer;
        this.offset = fileOffset;
    }

    @Override
    int prepareChunk(byte[] chunk, int bytesNeeded) throws IOException {
        int bytesToRead = Math.min(chunk.length, Math.min(bytesNeeded, buffer.remaining()));
        if (bytesToRead == 0) {
            return -1;
        }

        buffer.get(chunk, 0, bytesToRead);
        return bytesToRead;
    }

    @Override
    public boolean isAvailable() {
        return super.isAvailable() || buffer.hasRemaining();
    }
}
