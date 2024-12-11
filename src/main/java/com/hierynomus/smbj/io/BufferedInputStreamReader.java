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
import java.util.concurrent.atomic.AtomicBoolean;

public class BufferedInputStreamReader {
    private static final int EOF = -1;

    private final AtomicBoolean isEnd = new AtomicBoolean(false);

    private final BufferedInputStream inputStream;

    public BufferedInputStreamReader(BufferedInputStream inputStream) {
        this.inputStream = inputStream;
    }

    public int read(byte[] byteArray, int offset, int length) throws IOException {
        int readResult = inputStream.read(byteArray, offset, length);
        if (readResult == EOF) {
            isEnd.set(true);
        }
        return readResult;
    }

    public boolean isAvailable() {
        return !isEnd.get();
    }

    public void close() throws IOException {
        inputStream.close();
    }
}
