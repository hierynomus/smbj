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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.UnsupportedCharsetException;

public class Buffer<T extends Buffer<T>> {
    private static final Logger logger = LoggerFactory.getLogger(Buffer.class);

    public static class BufferException extends Exception {

        public BufferException(String message) {
            super(message);
        }
    }

    public static class PlainBuffer extends Buffer<PlainBuffer> {
        public PlainBuffer(Endian endiannes) {
            super(endiannes);
        }

        public PlainBuffer(Buffer<?> from) {
            super(from);
        }

        public PlainBuffer(byte[] data, Endian endianness) {
            super(data, endianness);
        }

        public PlainBuffer(int size, Endian endianness) {
            super(size, endianness);
        }
    }

    /**
     * The default size for a {@code Buffer} (256 bytes)
     */
    public static final int DEFAULT_SIZE = 256;

    /**
     * The maximum valid size of buffer (i.e. biggest power of two that can be represented as an int - 2^30)
     */
    public static final int MAX_SIZE = (1 << 30);

    protected static int getNextPowerOf2(int i) {
        int j = 1;
        while (j < i) {
            j <<= 1;
            if (j <= 0) throw new IllegalArgumentException("Cannot get next power of 2; " + i + " is too large");
        }
        return j;
    }

    private byte[] data;
    private Endian endianness;
    protected int rpos;
    protected int wpos;

    /**
     * @see #DEFAULT_SIZE
     */
    public Buffer(Endian endiannes) {
        this(DEFAULT_SIZE, endiannes);
    }

    public Buffer(Buffer<?> from) {
        data = new byte[(wpos = from.wpos - from.rpos)];
        endianness = from.endianness;
        System.arraycopy(from.data, from.rpos, data, 0, wpos);
    }

    public Buffer(byte[] data, Endian endianness) {
        this(data, true, endianness);
    }

    public Buffer(int size, Endian endianness) {
        this(new byte[getNextPowerOf2(size)], false, endianness);
    }

    private Buffer(byte[] data, boolean read, Endian endianness) {
        this.data = data;
        this.endianness = endianness;
        rpos = 0;
        wpos = read ? data.length : 0;
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
     * Returns the number of bytes still available to read from the buffer.
     *
     * @return The number of bytes available from the buffer.
     */
    public int available() {
        return wpos - rpos;
    }

    /**
     * Resets this buffer. The object becomes ready for reuse.
     * <p/>
     * <em>NOTE:</em> This does not erase the underlying byte array for performance reasons.
     */
    public void clear() {
        rpos = 0;
        wpos = 0;
    }

    /**
     * Returns the current reading position of the buffer.
     *
     * @return The current reading position
     */
    public int rpos() {
        return rpos;
    }

    /**
     * Set the current reading position.
     *
     * @param rpos The new reading position
     */
    public void rpos(int rpos) {
        this.rpos = rpos;
    }

    /**
     * Returns the current writing position of this buffer.
     *
     * @return The current writing position.
     */
    public int wpos() {
        return wpos;
    }

    /**
     * Set the current writing position.
     *
     * @param wpos The new writing position.
     */
    public void wpos(int wpos) {
        ensureCapacity(wpos - this.wpos);
        this.wpos = wpos;
    }

    /**
     * Ensure that there are at least <code>a</code> bytes available for reading from this buffer.
     *
     * @param a The number of bytes to ensure are at least available
     * @throws BufferException If there are less than <code>a</code> bytes available
     */
    protected void ensureAvailable(int a)
        throws BufferException {
        if (available() < a) {
            throw new BufferException("Underflow");
        }
    }

    /**
     * Ensure that there is at least <code>capacity</code> bytes available in the buffer for writing.
     * This call enlarges the buffer if there is less capacity than requested.
     *
     * @param capacity The capacity required/
     */
    public void ensureCapacity(int capacity) {
        if (data.length - wpos < capacity) {
            int cw = wpos + capacity;
            byte[] tmp = new byte[getNextPowerOf2(cw)];
            System.arraycopy(data, 0, tmp, 0, data.length);
            data = tmp;
        }
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
     * Read a boolean byte
     *
     * @return the {@code true} or {@code false} value read
     */
    public boolean readBoolean()
        throws BufferException {
        return readByte() != 0;
    }

    /**
     * Puts a boolean byte
     *
     * @param b the value
     * @return this
     */
    public Buffer<T> putBoolean(boolean b) {
        return putByte(b ? (byte) 1 : (byte) 0);
    }

    /**
     * Read a byte from the buffer
     *
     * @return the byte read
     */
    public byte readByte()
        throws BufferException {
        ensureAvailable(1);
        return data[rpos++];
    }

    /**
     * Writes a single byte into this buffer
     *
     * @param b
     * @return this
     */
    public Buffer<T> putByte(byte b) {
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
    public Buffer<T> putRawBytes(byte[] buf) {
        return putRawBytes(buf, 0, buf.length);
    }

    /**
     * Write the bytes of the passed byte array into this buffer, starting at offset, and writing length bytes.
     *
     * @param buf    The array of bytes to write
     * @param offset The offset at which to start reading from the passed array
     * @param length The number of bytes to write from the passed array
     * @return
     */
    public Buffer<T> putRawBytes(byte[] buf, int offset, int length) {
        ensureCapacity(length);
        System.arraycopy(buf, offset, data, wpos, length);
        wpos += length;
        return this;
    }

    /**
     * Copies the contents of provided buffer into this buffer
     *
     * @param buffer the {@code Buffer} to copy
     * @return this
     */
    public Buffer<T> putBuffer(Buffer<? extends Buffer<?>> buffer) {
        if (buffer != null) {
            int r = buffer.available();
            ensureCapacity(r);
            System.arraycopy(buffer.data, buffer.rpos, data, wpos, r);
            wpos += r;
        }
        return this;
    }

    /**
     * Read a uint16 from the buffer using the buffer's endianness.
     *
     * @return an int
     * @throws BufferException If this would cause an underflow (less than 2 bytes available)
     */
    public int readUInt16() throws BufferException {
        return readUInt16(endianness);
    }

    /**
     * Read a uint16 from the buffer using the specified endianness.
     *
     * @param endianness The endian (Big or Little) to use
     * @return an int
     * @throws BufferException If this would cause an underflow (less than 2 bytes available)
     */
    public int readUInt16(Endian endianness) throws BufferException {
        return endianness.readUInt16(this);
    }

    /**
     * Writes a uint16 integer in the buffer's endianness.
     *
     * @param uint16
     * @return this
     */
    public Buffer<T> putUInt16(int uint16) {
        return putUInt16(uint16, endianness);
    }

    /**
     * Writes a uint16 integer in the specified endianness.
     *
     * @param uint16
     * @param endianness The endian (Big or Little) to use
     * @return this
     */
    public Buffer<T> putUInt16(int uint16, Endian endianness) {
        endianness.writeUInt16(this, uint16);
        return this;
    }

    /**
     * Read a uint24 from the buffer using the buffer's endianness.
     *
     * @return an int
     * @throws BufferException If this would cause an underflow (less than 3 bytes available)
     */
    public int readUInt24() throws BufferException {
        return readUInt24(endianness);
    }

    /**
     * Read a uint24 from the buffer using the specified endianness.
     *
     * @param endianness The endian (Big or Little) to use
     * @return an int
     * @throws BufferException If this would cause an underflow (less than 3 bytes available)
     */
    public int readUInt24(Endian endianness) throws BufferException {
        return endianness.readUInt24(this);
    }

    /**
     * Writes a uint24 integer in the buffer's endianness.
     *
     * @param uint24
     * @return this
     */
    public Buffer<T> putUInt24(int uint24) {
        return putUInt24(uint24, endianness);
    }

    /**
     * Writes a uint24 integer in the specified endianness.
     *
     * @param uint24
     * @param endianness The endian (Big or Little) to use
     * @return this
     */
    public Buffer<T> putUInt24(int uint24, Endian endianness) {
        endianness.writeUInt24(this, uint24);
        return this;
    }

    /**
     * Read a uint32 from the buffer using the buffer's endianness.
     *
     * @return an int (possibly truncated)
     * @throws BufferException If this would cause an underflow (less than 4 bytes available)
     */
    public int readUInt32AsInt() throws BufferException {
        return (int) readUInt32();
    }

    /**
     * Read a uint32 from the buffer using the buffer's endianness.
     *
     * @return a long
     * @throws BufferException If this would cause an underflow (less than 4 bytes available)
     */
    public long readUInt32() throws BufferException {
        return readUInt32(endianness);
    }

    /**
     * Read a uint32 from the buffer using the specified endianness.
     *
     * @param endianness The endian (Big or Little) to use
     * @return a long
     * @throws BufferException If this would cause an underflow (less than 4 bytes available)
     */
    public long readUInt32(Endian endianness) throws BufferException {
        return endianness.readUInt32(this);
    }

    /**
     * Writes a uint32 integer in the buffer's endianness.
     *
     * @param uint32
     * @return this
     */
    public Buffer<T> putUInt32(long uint32) {
        return putUInt32(uint32, endianness);
    }

    /**
     * Writes a uint32 integer in the specified endianness.
     *
     * @param uint32
     * @param endianness The endian (Big or Little) to use
     * @return this
     */
    public Buffer<T> putUInt32(long uint32, Endian endianness) {
        endianness.writeUInt32(this, uint32);
        return this;
    }

    /**
     * Read a uint64 from the buffer using the buffer's endianness.
     *
     * @return a long
     * @throws BufferException If this would cause an underflow (less than 8 bytes available)
     */
    public long readUInt64() throws BufferException {
        return readUInt64(endianness);
    }

    /**
     * Read a uint64 from the buffer using the specified endianness.
     *
     * @param endianness The endian (Big or Little) to use
     * @return a long
     * @throws BufferException If this would cause an underflow (less than 8 bytes available)
     */
    public long readUInt64(Endian endianness) throws BufferException {
        return endianness.readUInt64(this);
    }

    /**
     * Writes a uint64 integer in the buffer's endianness.
     *
     * @param uint64
     * @return this
     */
    public Buffer<T> putUInt64(long uint64) {
        return putUInt64(uint64, endianness);
    }

    /**
     * Writes a uint64 integer in the specified endianness.
     *
     * @param uint64
     * @param endianness The endian (Big or Little) to use
     * @return this
     */
    public Buffer<T> putUInt64(long uint64, Endian endianness) {
        endianness.writeUInt64(this, uint64);
        return this;
    }

    /**
     * Writes a long in the buffer's endianness.
     * <p>
     * Note: unlike a uint64, a long can be <em>negative.</em>
     *
     * @param longVal
     * @return this
     */
    public Buffer<T> putLong(long longVal) {
        return putLong(longVal, endianness);
    }

    /**
     * Writes a long in the specified endianness.
     * <p>
     * Note: unlike a uint64, a long can be <em>negative</em> or <em>overflowed.</em>
     *
     * @param longVal
     * @return this
     */
    public Buffer<T> putLong(long longVal, Endian endianness) {
        endianness.writeLong(this, longVal);
        return this;
    }

    /**
     * Read a long from the buffer using the buffer's endianness.
     *
     * @return a long
     * @throws BufferException If this would cause an underflow (less than 8 bytes available)
     */
    public long readLong() throws BufferException {
        return readLong(endianness);
    }

    /**
     * Read a long from the buffer using the specified endianness.
     *
     * @param endianness The endian (Big or Little) to use
     * @return a long
     * @throws BufferException If this would cause an underflow (less than 8 bytes available)
     */
    public long readLong(Endian endianness) throws BufferException {
        return endianness.readLong(this);
    }

    /**
     * Read a string in the specified encoding.
     * <p/>
     * If the encoding is UTF-16, the buffer's endianness is used to determine the correct byte order.
     *
     * @param encoding The charset name to use.
     * @throws BufferException             If reading this string would cause an underflow
     * @throws UnsupportedCharsetException If the charset specified is not supported by the buffer.
     */
    public String readString(String encoding, int length) throws BufferException {
        return readString(Charset.forName(encoding), length, endianness);
    }

    /**
     * Read a string in the specified encoding.
     * <p/>
     * If the charset is UTF-16, the buffer's endianness is used to determine the correct byte order.
     *
     * @param charset The charset to use.
     * @throws BufferException             If reading this string would cause an underflow
     * @throws UnsupportedCharsetException If the charset specified is not supported by the buffer.
     */
    public String readString(Charset charset, int length) throws BufferException {
        return readString(charset, length, endianness);
    }

    private String readString(Charset charset, int length, Endian endianness) throws BufferException {
        switch (charset.name()) {
            case "UTF-16":
                return endianness.readUtf16String(this, length);
            case "UTF-16LE":
                return Endian.LE.readUtf16String(this, length);
            case "UTF-16BE":
                return Endian.BE.readUtf16String(this, length);
            case "UTF-8":
                return new String(readRawBytes(length), charset);
            default:
                throw new UnsupportedCharsetException(charset.name());
        }
    }

    /**
     * Read a null-terminated string in the specified encoding.
     * <p/>
     * If the charset is UTF-16, the buffer's endianness is used to determine the correct byte order.
     *
     * @param charset The charset to use.
     * @throws BufferException             If reading this string would cause an underflow
     * @throws UnsupportedCharsetException If the charset specified is not supported by the buffer.
     */
    public String readNullTerminatedString(Charset charset) throws BufferException {
        return readNullTerminatedString(charset, endianness);
    }

    private String readNullTerminatedString(Charset charset, Endian endianness) throws BufferException {
        switch (charset.name()) {
            case "UTF-16":
                return endianness.readNullTerminatedUtf16String(this);
            case "UTF-16LE":
                return Endian.LE.readNullTerminatedUtf16String(this);
            case "UTF-16BE":
                return Endian.BE.readNullTerminatedUtf16String(this);
            case "UTF-8":
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte b = readByte();
                while (b != 0) {
                    baos.write(b);
                    b = readByte();
                }
                return new String(baos.toByteArray(), charset);
            default:
                throw new UnsupportedCharsetException(charset.name());
        }
    }

    /**
     * Write the string in the specified charset.
     * <p/>
     * If the charset is UTF-16, the buffer's endianness is used to determine the correct byte order.
     *
     * @param string  The string to write
     * @param charset The charset to use
     * @return this
     * @throws UnsupportedCharsetException If the charset specified is not supported by the buffer.
     */
    public Buffer<T> putString(String string, Charset charset) {
        return putString(string, charset, endianness);
    }

    private Buffer<T> putString(String string, Charset charset, Endian endianness) {
        switch (charset.name()) {
            case "UTF-16":
                endianness.writeUtf16String(this, string);
                break;
            case "UTF-16LE":
                Endian.LE.writeUtf16String(this, string);
                break;
            case "UTF-16BE":
                Endian.BE.writeUtf16String(this, string);
                break;
            case "UTF-8":
                byte[] bytes = string.getBytes(charset);
                putRawBytes(bytes);
                break;
            default:
                throw new UnsupportedCharsetException(charset.name());
        }
        return this;
    }

    /**
     * Write the string with an additional null-terminator in the specified charset.
     * <p/>
     * If the charset is UTF-16, the buffer's endianness is used to determine the correct byte order.
     *
     * @param string  The string to write
     * @param charset The charset to use
     * @return this
     * @throws UnsupportedCharsetException If the charset specified is not supported by the buffer.
     */
    public Buffer<T> putNullTerminatedString(String string, Charset charset) {
        return putNullTerminatedString(string, charset, endianness);
    }

    private Buffer<T> putNullTerminatedString(String string, Charset charset, Endian endianness) {
        switch (charset.name()) {
            case "UTF-16":
                endianness.writeNullTerminatedUtf16String(this, string);
                break;
            case "UTF-16LE":
                Endian.LE.writeNullTerminatedUtf16String(this, string);
                break;
            case "UTF-16BE":
                Endian.BE.writeNullTerminatedUtf16String(this, string);
                break;
            case "UTF-8":
                byte[] bytes = string.getBytes(charset);
                putRawBytes(bytes);
                putByte((byte) 0);
                break;
            default:
                throw new UnsupportedCharsetException(charset.name());
        }
        return this;
    }


    /**
     * Skip the specified number of bytes.
     *
     * @param length The number of bytes to skip
     * @return this
     * @throws BufferException If this would cause an underflow (less than <code>length</code>) bytes available).
     */
    public Buffer<T> skip(int length) throws BufferException {
        ensureAvailable(length);
        rpos += length;
        return this;
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
        return "Buffer [rpos=" + rpos + ", wpos=" + wpos + ", size=" + data.length + "]";
    }

    public InputStream asInputStream() {
        return new InputStream() {
            @Override
            public int read() throws IOException {
                try {
                    return Buffer.this.readByte() & 0xFF;
                } catch (BufferException e) {
                    throw new IOException(e);
                }
            }

            @Override
            public int read(byte[] b) throws IOException {
                try {
                    Buffer.this.readRawBytes(b);
                    return b.length;
                } catch (BufferException e) {
                    throw new IOException(e);
                }
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                return super.read(b, off, len);
            }

            @Override
            public long skip(long n) throws IOException {
                Buffer.this.rpos((int) n);
                return n;
            }

            @Override
            public int available() throws IOException {
                return Buffer.this.available();
            }
        };
    }
}
