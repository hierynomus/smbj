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

import com.hierynomus.smbj.common.SMBRuntimeException;

import java.io.*;

public class FileByteChunkProvider extends ByteChunkProvider implements Closeable {

    private File file;
    private BufferedInputStream fis;

    public FileByteChunkProvider(File file) throws FileNotFoundException {
        this.file = file;
        fis = new BufferedInputStream(new FileInputStream(file), CHUNK_SIZE);
    }

    public FileByteChunkProvider(File file, long offset) throws IOException {
        this.file = file;
        fis = new BufferedInputStream(new FileInputStream(file), CHUNK_SIZE);
        ensureSkipped(fis, offset);
        this.offset = offset;
    }

    private void ensureSkipped(final BufferedInputStream fis, final long offset) throws IOException {
        long skipped = 0;
        while (skipped < offset && fis.available() > 0) {
            skipped += fis.skip(offset);
        }

        if (skipped < offset) {
            throw new IOException("Was unable to go to the requested offset of " + offset + " of file " + file);
        }
    }

    @Override
    protected int getChunk(byte[] chunk) throws IOException {
        int count = 0;
        int read = 0;
        while (count < CHUNK_SIZE && ((read = fis.read(chunk, count, CHUNK_SIZE - count)) != -1)) {
            count += read;
        }
        return count;
    }

    @Override
    public int bytesLeft() {
        try {
            return fis.available();
        } catch (IOException e) {
            throw new SMBRuntimeException(e);
        }
    }

    @Override
    public boolean isAvailable() {
        return bytesLeft() > 0;
    }

    @Override
    public void close() throws IOException {
        if (fis != null) {
            try {
                fis.close();
            } finally {
                fis = null;
            }
        }
    }
}
