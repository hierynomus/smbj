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

public class FileByteChunkProvider extends ByteChunkProvider {

    private File file;
    private BufferedInputStream fis;

    public FileByteChunkProvider(File file) throws FileNotFoundException {
        this.file = file;
        fis = new BufferedInputStream(new FileInputStream(file), CHUNK_SIZE);
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
}
