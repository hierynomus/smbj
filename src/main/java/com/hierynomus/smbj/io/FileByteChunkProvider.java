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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class FileByteChunkProvider extends ByteChunkProvider {

    private File file;
    private InputStreamByteChunkProvider underlyingProvider;

    public FileByteChunkProvider(File file) throws IOException {
        this(file, 0);
    }

    public FileByteChunkProvider(File file, long offset) throws IOException {
        this.file = file;
        FileInputStream fis = new FileInputStream(file);
        underlyingProvider = new InputStreamByteChunkProvider(fis);
        ensureSkipped(fis, offset);
        this.offset = offset;
    }

    private void ensureSkipped(final FileInputStream fis, final long offset) throws IOException {
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
        return underlyingProvider.getChunk(chunk);
    }

    @Override
    public int bytesLeft() {
        return underlyingProvider.bytesLeft();
    }

    @Override
    public boolean isAvailable() {
        return underlyingProvider.isAvailable();
    }

    @Override
    public void close() throws IOException {
        underlyingProvider.close();
    }
}
