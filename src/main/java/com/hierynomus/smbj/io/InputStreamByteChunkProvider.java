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
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.smbj.common.SMBRuntimeException;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;

public class InputStreamByteChunkProvider extends ByteChunkProvider {

    private BufferedInputStream is;
    private BufferByteChunkProvider cachingProvider;
    private Buffer<Buffer.PlainBuffer> buffer;

    public InputStreamByteChunkProvider(InputStream is) {
        this.buffer = new Buffer.PlainBuffer(Endian.BE);
        this.cachingProvider = new BufferByteChunkProvider(buffer);
        if (is instanceof BufferedInputStream)
            this.is = (BufferedInputStream) is;
        else
            this.is = new BufferedInputStream(is);
    }

    @Override
    public void prepareWrite(int maxBytesToPrepare) {
        if (is == null) {
            return;
        }

        byte[] chunk = new byte[1024];

        // Before each prepareWrite, compact the buffer to minimize size growth
        buffer.compact();
        
        int bytesNeeded = maxBytesToPrepare - buffer.available();
        int read;
        try {
            while (bytesNeeded > 0) {
                read = is.read(chunk, 0, chunk.length);
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
        try {
            return cachingProvider.isAvailable() || is.available() > 0;
        } catch (IOException e) {
            throw new SMBRuntimeException(e);
        }
    }

    @Override
    public void close() throws IOException {
        cachingProvider.close();

        if (is != null) {
            try {
                is.close();
            } finally {
                is = null;
            }
        }
    }
}
