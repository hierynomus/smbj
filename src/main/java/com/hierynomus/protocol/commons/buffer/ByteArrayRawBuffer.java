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
package com.hierynomus.protocol.commons.buffer;

import com.hierynomus.protocol.commons.ByteArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ByteArrayRawBuffer implements RawBuffer<ByteArrayRawBuffer> {
    private static final Logger logger = LoggerFactory.getLogger(ByteArrayRawBuffer.class);

    /**
     * The default size for a {@code Buffer} (256 bytes)
     */
    private static final int DEFAULT_SIZE = 256;

    /**
     * The maximum valid size of buffer (i.e. biggest power of two that can be represented as an int - 2^30)
     */
    public static final int MAX_SIZE = (1 << 30);

    private static int getNextPowerOf2(int i) {
        int j = 1;
        while (j < i) {
            j <<= 1;
            if (j <= 0) throw new IllegalArgumentException("Cannot get next power of 2; " + i + " is too large");
        }
        return j;
    }

    protected byte[] data;
    protected int rpos;
    protected int wpos;

    /**
     * @see #DEFAULT_SIZE
     */
    public ByteArrayRawBuffer() {
        this(DEFAULT_SIZE);
    }

    public ByteArrayRawBuffer(byte[] data) {
        this(data, true);
    }

    public ByteArrayRawBuffer(int size) {
        this(new byte[getNextPowerOf2(size)], false);
    }

    private ByteArrayRawBuffer(byte[] data, boolean read) {
        this.data = data;
        rpos = 0;
        wpos = read ? data.length : 0;
    }

    /**
     * Compact this buffer by truncating the read bytes from the array.
     */
    public void compact() {
        logger.debug("Compacting...");
        if (available() > 0) {
            System.arraycopy(data, rpos, data, 0, wpos - rpos);
        }
        wpos -= rpos;
        rpos = 0;
    }

    public byte[] getCompactData() {
        final int len = available();
        if (len > 0) {
            byte[] b = new byte[len];
            System.arraycopy(data, rpos, b, 0, len);
            return b;
        } else {
            return new byte[0];
        }
    }


    /**
     * Returns the underlying byte array.
     * <p/>
     * <em>NOTE:</em> Be careful, the structure is mutable.
     *
     * @return The underlying byte array
     */
    public byte[] array() {
        return data;
    }


    /**
     * Read a byte from the buffer
     *
     * @return the byte read
     */
    @Override
    public byte readByte()
        throws BufferException {
        ensureAvailable(1);
        return data[rpos++];
    }

    /**
     * Writes a single byte into this buffer
     *
     * @param b The byte value to write
     * @return this
     */
    @Override
    public RawOutputBuffer<ByteArrayRawBuffer> putByte(byte b) {
        ensureCapacity(1);
        data[wpos++] = b;
        return this;
    }

    /**
     * Read <code>length</code> raw bytes from the buffer into a newly allocated byte array of length <code>length</code>.
     *
     * @param length The number of bytes to read.
     * @return a newly allocated byte array of <code>length</code> containing the read bytes.
     * @throws BufferException If the read operation would cause an underflow (less than <code>length</code> bytes available)
     */
    @Override
    public byte[] readRawBytes(int length) throws BufferException {
        byte[] bytes = new byte[length];
        readRawBytes(bytes);
        return bytes;
    }

    /**
     * Read a raw byte array from the buffer into the passed byte array. Will try to read exactly the size of array bytes.
     *
     * @param buf The array to write the read bytes into
     * @throws BufferException If the read operation would cause an underflow (less bytes available than array size)
     */
    @Override
    public void readRawBytes(byte[] buf)
        throws BufferException {
        readRawBytes(buf, 0, buf.length);
    }

    /**
     * Read a raw byte array from the buffer into the passed byte array starting at offset, and reading exactly length bytes.
     *
     * @param buf    The array to write the read bytes into
     * @param offset The offset at which to start writing into the array
     * @param length The number of bytes to read from this buffer
     * @throws BufferException If the read operation would cause an underflow (less than length bytes available)
     */
    @Override
    public void readRawBytes(byte[] buf, int offset, int length)
        throws BufferException {
        ensureAvailable(length);
        System.arraycopy(data, rpos, buf, offset, length);
        rpos += length;
    }

    /**
     * Write the bytes of the passed byte array into this buffer.
     *
     * @param buf The array of bytes to write.
     * @return this.
     */
    @Override
    public RawOutputBuffer<ByteArrayRawBuffer> putRawBytes(byte[] buf) {
        return putRawBytes(buf, 0, buf.length);
    }

    /**
     * Write the bytes of the passed byte array into this buffer, starting at offset, and writing length bytes.
     *
     * @param buf    The array of bytes to write
     * @param offset The offset at which to start reading from the passed array
     * @param length The number of bytes to write from the passed array
     * @return this.
     */
    @Override
    public RawOutputBuffer<ByteArrayRawBuffer> putRawBytes(byte[] buf, int offset, int length) {
        ensureCapacity(length);
        System.arraycopy(buf, offset, data, wpos, length);
        wpos += length;
        return this;
    }

    /**
     * Ensure that there are at least <code>a</code> bytes available for reading from this buffer.
     *
     * @param a The number of bytes to ensure are at least available
     * @throws BufferException If there are less than <code>a</code> bytes available
     */
    private void ensureAvailable(int a)
        throws BufferException {
        if (available() < a) {
            throw new BufferException("Underflow");
        }
    }

    /**
     * Returns the number of bytes still available to read from the buffer.
     *
     * @return The number of bytes available from the buffer.
     */
    @Override
    public int available() {
        return wpos - rpos;
    }

    /**
     * Ensure that there is at least <code>capacity</code> bytes available in the buffer for writing.
     * This call enlarges the buffer if there is less capacity than requested.
     *
     * @param capacity The capacity required/
     */
    private void ensureCapacity(int capacity) {
        if (data.length - wpos < capacity) {
            int cw = wpos + capacity;
            byte[] tmp = new byte[getNextPowerOf2(cw)];
            System.arraycopy(data, 0, tmp, 0, data.length);
            data = tmp;
        }
    }

    /**
     * Returns the current reading position of the buffer.
     *
     * @return The current reading position
     */
    @Override
    public int rpos() {
        return rpos;
    }

    /**
     * Set the current reading position.
     *
     * @param rpos The new reading position
     */
    @Override
    public void rpos(int rpos) {
        this.rpos = rpos;
    }

    /**
     * Returns the current writing position of this buffer.
     *
     * @return The current writing position.
     */
    @Override
    public int wpos() {
        return wpos;
    }

    @Override
    public void clear() {
        this.rpos = 0;
        this.wpos = 0;
    }

    @Override
    public void skip(final int length) throws BufferException {
        ensureAvailable(length);
        rpos += length;
    }

    /**
     * Gives a readable snapshot of the buffer in hex. This is useful for debugging.
     *
     * @return snapshot of the buffer as a hex string with each octet delimited by a space
     */
    public String printHex() {
        return ByteArrayUtils.printHex(array(), rpos(), available());
    }


    @Override
    public String toString() {
        return "ByteArrayBuffer[rpos=" + rpos + ", wpos=" + wpos + ", size=" + data.length + "]";
    }

}
