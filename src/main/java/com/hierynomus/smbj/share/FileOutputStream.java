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
package com.hierynomus.smbj.share;

import com.hierynomus.smbj.ProgressListener;
import com.hierynomus.smbj.io.ByteChunkProvider;
import com.hierynomus.protocol.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;

class FileOutputStream extends OutputStream {

    private File file;
    private ProgressListener progressListener;
    private boolean isClosed = false;
    private ByteArrayProvider provider;

    private static final Logger logger = LoggerFactory.getLogger(FileOutputStream.class);

    FileOutputStream(File file, int bufferSize, ProgressListener progressListener) {
        this.file = file;
        this.progressListener = progressListener;
        this.provider = new ByteArrayProvider(bufferSize);
    }

    @Override
    public void write(int b) throws IOException {
        verifyConnectionNotClosed();

        if (provider.isBufferFull()) {
            flush();
        }

        if (!provider.isBufferFull()) {
            provider.writeByte(b);
        }
    }

    @Override
    public void write(byte b[]) throws IOException {
        write(b, 0, b.length);
    }

    @Override
    public void write(byte b[], int off, int len) throws IOException {
        verifyConnectionNotClosed();
        int offset = off;
        int length = len;
        do {
            int writeLen = Math.min(length, provider.maxSize());

            while (provider.isBufferFull(writeLen)) {
                flush();
            }

            if (!provider.isBufferFull()) {
                provider.writeBytes(b, offset, writeLen);
            }
            
            offset += writeLen;
            length -= writeLen;
            
        } while (length > 0);
    }

    @Override
    public void flush() throws IOException {
        verifyConnectionNotClosed();
        if (provider.isAvailable()) {
            sendWriteRequest();
        }
    }

    private void sendWriteRequest() throws TransportException {
        file.write(provider, progressListener);
    }

    @Override
    public void close() throws IOException {

        while (provider.isAvailable()) {
            sendWriteRequest();
        }

        provider.reset();

        isClosed = true;
        file = null;
        logger.debug("EOF, {} bytes written", provider.getOffset());
    }

    private void verifyConnectionNotClosed() throws IOException {
        if (isClosed) throw new IOException("Stream is closed");
    }

    private static class ByteArrayProvider extends ByteChunkProvider {

        private RingBuffer buf;

        private ByteArrayProvider(int maxWriteSize) {
            this.buf = new RingBuffer(maxWriteSize);
        }

        @Override
        public boolean isAvailable() {
            return !buf.isEmpty();
        }

        @Override
        protected int getChunk(byte[] chunk) throws IOException {
            return buf.read(chunk);
        }

        @Override
        public int bytesLeft() {
            return buf.size();
        }

        public void writeBytes(byte[] b, int off, int len) {
            buf.write(b, off, len);
        }

        public void writeByte(int b) {
            buf.write(b);
        }

        public boolean isBufferFull() {
            return buf.isFull();
        }

        public boolean isBufferFull(int len) {
            return buf.isFull(len);
        }

        public int maxSize() {
            return buf.maxSize();
        }

        private void reset() {
            this.buf = null;
        }
    }
}
