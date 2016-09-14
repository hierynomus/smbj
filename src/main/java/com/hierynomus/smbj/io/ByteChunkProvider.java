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
import com.hierynomus.smbj.common.SMBRuntimeException;

import java.io.IOException;
import java.io.OutputStream;

public abstract class ByteChunkProvider {
    static final int CHUNK_SIZE = 64 * 1024;

    protected long offset = 0;

    public abstract boolean isAvailable();

    public void writeChunk(OutputStream os) {
        byte[] chunk = new byte[CHUNK_SIZE];
        try {
            int size = getChunk(chunk);
            os.write(chunk, 0, size);
            offset += size;
        } catch (IOException e) {
            throw new SMBRuntimeException(e);
        }
    }

    public void writeChunks(Buffer<?> buffer, int nrChunks) {
        byte[] chunk = new byte[CHUNK_SIZE];
        for (int i = 0; i < nrChunks; i++) {
            try {
                int size = getChunk(chunk);
                buffer.putRawBytes(chunk, 0, size);
                offset += size;
            } catch (IOException e) {
                throw new SMBRuntimeException(e);
            }
        }
    }

    public void writeChunk(Buffer<?> buffer) {
        byte[] chunk = new byte[CHUNK_SIZE];
        try {
            int size = getChunk(chunk);
            buffer.putRawBytes(chunk, 0, size);
            offset += size;
        } catch (IOException e) {
            throw new SMBRuntimeException(e);
        }
    }

    public long getOffset() {
        return offset;
    }

    protected abstract int getChunk(byte[] chunk) throws IOException;

    public abstract int bytesLeft();
}
