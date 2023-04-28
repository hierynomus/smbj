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

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;

import com.hierynomus.smbj.common.SMBRuntimeException;

public class InputStreamByteChunkProvider extends CachingByteChunkProvider {

    private BufferedInputStream is;
    private boolean close;

    public InputStreamByteChunkProvider(InputStream is) {
        super();
        if (is instanceof BufferedInputStream)
            this.is = (BufferedInputStream) is;
        else {
            this.is = new BufferedInputStream(is);
            this.close = true; // We control the is, so we close it
        }

    }

    @Override
    int prepareChunk(byte[] chunk, int bytesNeeded) throws IOException {
        int toRead = Math.min(bytesNeeded, chunk.length);
        if (toRead == 0) {
            return -1;
        }

        return is.read(chunk, 0, toRead);
    }

    @Override
    public boolean isAvailable() {
        try {
            return super.isAvailable() || (is != null && is.available() > 0);
        } catch (IOException e) {
            throw new SMBRuntimeException(e);
        }
    }

    @Override
    public void close() throws IOException {
        super.close();

        if (is != null && close) {
            try {
                is.close();
            } finally {
                is = null;
            }
        }
    }
}
