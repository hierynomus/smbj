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

public class RingBuffer {

    private byte[] buf;
    private int readIndex;
    private int writeIndex;
    private int size;

    public RingBuffer(int maxSize) {
        buf = new byte[maxSize];
    }

    public void write(byte[] b) {

        if (b.length > getAvailableSize())
            throw new IndexOutOfBoundsException("Size of bytes to be written is greater than available buffer space");

        writeBytes(b);
        size += b.length;
    }

    public byte[] read(int i) {
        if (i == 0)
            throw new IllegalArgumentException("Read size should be more than zero");
        if (i > getUsedSize())
            throw new IndexOutOfBoundsException("Read size is greater than available bytes");
        byte[] b = new byte[i];
        readBytes(b, i);
        size -= i;
        return b;
    }

    public int getUsedSize() {
        return size;
    }

    public int getAvailableSize() {
        return buf.length - size;
    }

    private void writeBytes(byte[] b) {
        int i = b.length;
        if (writeIndex + i <= buf.length) {
            System.arraycopy(b, 0, buf, writeIndex, i);
            writeIndex += i;
        } else {
            int bytesToEnd = buf.length - writeIndex;
            System.arraycopy(b, 0, buf, writeIndex, bytesToEnd);
            System.arraycopy(b, bytesToEnd, buf, bytesToEnd, i - bytesToEnd);
            writeIndex = i - bytesToEnd;
        }
    }

    private void readBytes(byte[] b, int i) {
        if (readIndex + i <= buf.length) {
            System.arraycopy(buf, readIndex, b, 0, i);
            readIndex += i;
        } else {
            int bytesToEnd = buf.length - readIndex;
            System.arraycopy(buf, readIndex, b, 0, bytesToEnd);
            System.arraycopy(buf, 0, b, bytesToEnd, i - bytesToEnd);
            readIndex = i - bytesToEnd;
        }
    }
}

