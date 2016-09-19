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

class RingBuffer {

    private byte[] buf;
    private int writeIndex;
    private int size;

    public RingBuffer(int maxSize) {
        buf = new byte[maxSize];
    }


    public void write(byte[] b, int off, int len) {

        if (b.length - off < len) {
            throw new IllegalArgumentException("Bytes to write do not exist in source");
        }

        if (len > buf.length - size) {
            throw new IndexOutOfBoundsException("Size of bytes to be written is greater than available buffer space");
        }

        writeBytes(b, off, len);
        size += len;
    }

    public void write(int b) {
        write(new byte[]{(byte) b}, 0, 1);
    }


    public int read(byte[] chunk) {

        int len = size < chunk.length ? size : chunk.length;
        readBytes(chunk, len);
        size -= len;
        return len;
    }

    public int getUsedSize() {
        return size;
    }

    private void readBytes(byte[] b, int i) {
        int readIndex = writeIndex - size;
        if (readIndex > 0) {
            System.arraycopy(buf, readIndex, b, 0, i);
        } else {
            readIndex += buf.length;
            int bytesToEnd = buf.length - readIndex;
            System.arraycopy(buf, readIndex, b, 0, bytesToEnd);
            System.arraycopy(buf, 0, b, bytesToEnd, i - bytesToEnd);
        }
    }

    private void writeBytes(byte[] b, int off, int len) {
        if (writeIndex + len <= buf.length) {
            System.arraycopy(b, off, buf, writeIndex, len);
            writeIndex += len;
        } else {
            int bytesToEnd = buf.length - writeIndex;
            System.arraycopy(b, off, buf, writeIndex, bytesToEnd);
            System.arraycopy(b, bytesToEnd, buf, bytesToEnd, len - bytesToEnd);
            writeIndex = len - bytesToEnd;
        }
    }

    public boolean isFull() {
        return size == buf.length;
    }

    public boolean isFull(int len) {
        return size + len > buf.length;
    }

    public boolean hasData() {
        return size > 0;
    }
}

