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
