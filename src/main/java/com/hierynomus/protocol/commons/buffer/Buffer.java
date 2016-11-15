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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.UnsupportedCharsetException;

public class Buffer<T extends Buffer<T>> implements RawBuffer<T> {

    public static class PlainBuffer extends Buffer<PlainBuffer> {
        public PlainBuffer(Endian endiannes) {
            super(endiannes);
        }

        public PlainBuffer(RawBuffer<?> from, Endian endianness) {
            super(from, endianness);
        }

        public PlainBuffer(byte[] bytes, Endian endianness) {
            super(new ByteArrayRawBuffer(bytes), endianness);
        }
    }

    private RawBuffer<?> rawBuffer;
    private Endian endianness;

    public Buffer(Endian endiannes) {
        this(new ByteArrayRawBuffer(), endiannes);
    }

    public Buffer(RawBuffer rawBuffer, Endian endianness) {
        this.rawBuffer = rawBuffer;
        this.endianness = endianness;
    }

    /**
     * Returns the number of bytes still available to read from the buffer.
     *
     * @return The number of bytes available from the buffer.
     */
    public int available() {
        return rawBuffer.available();
    }

    /**
     * Resets this buffer. The object becomes ready for reuse.
     * <p/>
     * <em>NOTE:</em> This does not erase the underlying byte array for performance reasons.
     */
    public void clear() {
        rawBuffer.clear();
    }

    /**
     * Returns the current reading position of the buffer.
     *
     * @return The current reading position
     */
    public int rpos() {
        return rawBuffer.rpos();
    }

    /**
     * Set the current reading position.
     *
     * @param rpos The new reading position
     */
    public void rpos(int rpos) {
        rawBuffer.rpos(rpos);
    }

    /**
     * Returns the current writing position of this buffer.
     *
     * @return The current writing position.
     */
    public int wpos() {
        return rawBuffer.wpos();
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
     * @param b The boolean value to write
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
        return rawBuffer.readByte();
    }

    /**
     * Writes a single byte into this buffer
     *
     * @param b The byte value to write
     * @return this
     */
    public Buffer<T> putByte(byte b) {
        rawBuffer.putByte(b);
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
        return rawBuffer.readRawBytes(length);
    }

    /**
     * Read a raw byte array from the buffer into the passed byte array. Will try to read exactly the size of array bytes.
     *
     * @param buf The array to write the read bytes into
     * @throws BufferException If the read operation would cause an underflow (less bytes available than array size)
     */
    public void readRawBytes(byte[] buf) throws BufferException {
        rawBuffer.readRawBytes(buf, 0, buf.length);
    }

    /**
     * Read a raw byte array from the buffer into the passed byte array starting at offset, and reading exactly length bytes.
     *
     * @param buf    The array to write the read bytes into
     * @param offset The offset at which to start writing into the array
     * @param length The number of bytes to read from this buffer
     * @throws BufferException If the read operation would cause an underflow (less than length bytes available)
     */
    public void readRawBytes(byte[] buf, int offset, int length) throws BufferException {
        rawBuffer.readRawBytes(buf, offset, length);
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
        rawBuffer.putRawBytes(buf, offset, length);
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
        return endianness.readUInt16(rawBuffer);
    }

    /**
     * Writes a uint16 integer in the buffer's endianness.
     *
     * @param uint16 The uint16 value to write
     * @return this
     */
    public Buffer<T> putUInt16(int uint16) {
        return putUInt16(uint16, endianness);
    }

    /**
     * Writes a uint16 integer in the specified endianness.
     *
     * @param uint16     The uint16 value to write
     * @param endianness The endian (Big or Little) to use
     * @return this
     */
    public Buffer<T> putUInt16(int uint16, Endian endianness) {
        endianness.writeUInt16(rawBuffer, uint16);
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
        return endianness.readUInt24(rawBuffer);
    }

    /**
     * Writes a uint24 integer in the buffer's endianness.
     *
     * @param uint24 The uint24 value to write
     * @return this
     */
    public Buffer<T> putUInt24(int uint24) {
        return putUInt24(uint24, endianness);
    }

    /**
     * Writes a uint24 integer in the specified endianness.
     *
     * @param uint24     The uint24 value to write
     * @param endianness The endian (Big or Little) to use
     * @return this
     */
    public Buffer<T> putUInt24(int uint24, Endian endianness) {
        endianness.writeUInt24(rawBuffer, uint24);
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
        return endianness.readUInt32(rawBuffer);
    }

    /**
     * Writes a uint32 integer in the buffer's endianness.
     *
     * @param uint32 The uint32 value to write
     * @return this
     */
    public Buffer<T> putUInt32(long uint32) {
        return putUInt32(uint32, endianness);
    }

    /**
     * Writes a uint32 integer in the specified endianness.
     *
     * @param uint32     The uint32 value to write
     * @param endianness The endian (Big or Little) to use
     * @return this
     */
    public Buffer<T> putUInt32(long uint32, Endian endianness) {
        endianness.writeUInt32(rawBuffer, uint32);
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
        return endianness.readUInt64(rawBuffer);
    }

    /**
     * Writes a uint64 integer in the buffer's endianness.
     *
     * @param uint64 The uint64 value to write
     * @return this
     */
    public Buffer<T> putUInt64(long uint64) {
        return putUInt64(uint64, endianness);
    }

    /**
     * Writes a uint64 integer in the specified endianness.
     *
     * @param uint64     The uint64 value to write
     * @param endianness The endian (Big or Little) to use
     * @return this
     */
    public Buffer<T> putUInt64(long uint64, Endian endianness) {
        endianness.writeUInt64(rawBuffer, uint64);
        return this;
    }

    /**
     * Writes a long in the buffer's endianness.
     * <p>
     * Note: unlike a uint64, a long can be <em>negative.</em>
     *
     * @param longVal The long value to write
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
     * @param longVal The long value to write
     * @return this
     */
    public Buffer<T> putLong(long longVal, Endian endianness) {
        endianness.writeLong(rawBuffer, longVal);
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
        return endianness.readLong(rawBuffer);
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
                return endianness.readUtf16String(rawBuffer, length);
            case "UTF-16LE":
                return Endian.LE.readUtf16String(rawBuffer, length);
            case "UTF-16BE":
                return Endian.BE.readUtf16String(rawBuffer, length);
            case "UTF-8":
                return new String(readRawBytes(length), charset);
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
                endianness.writeUtf16String(rawBuffer, string);
                break;
            case "UTF-16LE":
                Endian.LE.writeUtf16String(rawBuffer, string);
                break;
            case "UTF-16BE":
                Endian.BE.writeUtf16String(rawBuffer, string);
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
     * Skip the specified number of bytes.
     *
     * @param length The number of bytes to skip
     * @throws BufferException If this would cause an underflow (less than <code>length</code>) bytes available).
     */
    public void skip(int length) throws BufferException {
        rawBuffer.skip(length);
    }

    @Override
    public void compact() {
        rawBuffer.compact();
    }

    @Override
    public byte[] getCompactData() {
        return rawBuffer.getCompactData();
    }

    @Override
    public byte[] array() {
        return rawBuffer.array();
    }



    @Override
    public String toString() {
        return "Buffer [rawBuffer=" + rawBuffer.toString() + "]";
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
