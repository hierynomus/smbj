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

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.smbj.common.SMBRuntimeException;

abstract class CachingByteChunkProvider extends ByteChunkProvider {
    private BufferByteChunkProvider cachingProvider;
    private Buffer<Buffer.PlainBuffer> buffer;

    CachingByteChunkProvider() {
        this.buffer = new Buffer.PlainBuffer(Endian.BE);
        this.cachingProvider = new BufferByteChunkProvider(buffer);
    }

    @Override
    public void prepareWrite(int maxBytesToPrepare) {
        if (buffer == null) {
            return;
        }

        byte[] chunk = new byte[1024];

        // Before each prepareWrite, compact the buffer to minimize size growth
        buffer.compact();

        int bytesNeeded = maxBytesToPrepare - buffer.available();
        int read;
        try {
            while (bytesNeeded > 0) {
                read = prepareChunk(chunk, bytesNeeded);
                if (read == -1) {
                    break;
                }

                // Write the data to the buffer
                buffer.putRawBytes(chunk, 0, read);
                bytesNeeded -= read;
            }
        } catch (IOException e) {
            throw new SMBRuntimeException(e);
        }
    }

    abstract int prepareChunk(byte[] chunk, int bytesNeeded) throws IOException;

    @Override
    protected int getChunk(byte[] chunk) throws IOException {
        return cachingProvider.getChunk(chunk);
    }

    @Override
    public int bytesLeft() {
        return cachingProvider.bytesLeft();
    }

    @Override
    public boolean isAvailable() {
        return cachingProvider.isAvailable();
    }

    @Override
    public void close() throws IOException {
        cachingProvider.close();
    }
}
