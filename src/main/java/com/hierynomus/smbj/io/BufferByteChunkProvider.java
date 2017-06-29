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

import com.hierynomus.protocol.commons.buffer.Buffer;

import java.io.IOException;

public class BufferByteChunkProvider extends ByteChunkProvider {
    private Buffer<?> buffer;

    public BufferByteChunkProvider(Buffer<?> buffer) {
        this.buffer = buffer;
    }

    @Override
    public boolean isAvailable() {
        return buffer.available() > 0;
    }

    @Override
    protected int getChunk(byte[] chunk) throws IOException {
        int toRead = chunk.length;
        if (buffer.available() < chunk.length) {
            toRead = buffer.available();
        }

        try {
            buffer.readRawBytes(chunk, 0, toRead);
        } catch (Buffer.BufferException e) {
            throw new IOException(e);
        }
        return toRead;
    }

    @Override
    public int bytesLeft() {
        return buffer.available();
    }
}
