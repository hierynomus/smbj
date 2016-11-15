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

import java.nio.charset.Charset;
import java.nio.charset.UnsupportedCharsetException;

public interface InputBuffer extends RawInputBuffer {
    /**
     * Read a uint16 from the buffer using the buffer's endianness.
     *
     * @return an int
     * @throws BufferException If this would cause an underflow (less than 2 bytes available)
     */
    int readUInt16() throws BufferException;

    /**
     * Read a uint16 from the buffer using the specified endianness.
     *
     * @param endianness The endian (Big or Little) to use
     * @return an int
     * @throws BufferException If this would cause an underflow (less than 2 bytes available)
     */
    int readUInt16(Endian endianness) throws BufferException;

    /**
     * Read a uint24 from the buffer using the buffer's endianness.
     *
     * @return an int
     * @throws BufferException If this would cause an underflow (less than 3 bytes available)
     */
    int readUInt24() throws BufferException;

    /**
     * Read a uint24 from the buffer using the specified endianness.
     *
     * @param endianness The endian (Big or Little) to use
     * @return an int
     * @throws BufferException If this would cause an underflow (less than 3 bytes available)
     */
    int readUInt24(Endian endianness) throws BufferException;

    /**
     * Read a uint32 from the buffer using the buffer's endianness.
     *
     * @return an int (possibly truncated)
     * @throws BufferException If this would cause an underflow (less than 4 bytes available)
     */
    int readUInt32AsInt() throws BufferException;

    /**
     * Read a uint32 from the buffer using the buffer's endianness.
     *
     * @return a long
     * @throws BufferException If this would cause an underflow (less than 4 bytes available)
     */
    long readUInt32() throws BufferException;

    /**
     * Read a uint32 from the buffer using the specified endianness.
     *
     * @param endianness The endian (Big or Little) to use
     * @return a long
     * @throws BufferException If this would cause an underflow (less than 4 bytes available)
     */
    long readUInt32(Endian endianness) throws BufferException;

    /**
     * Read a uint64 from the buffer using the buffer's endianness.
     *
     * @return a long
     * @throws BufferException If this would cause an underflow (less than 8 bytes available)
     */
    long readUInt64() throws BufferException;

    /**
     * Read a uint64 from the buffer using the specified endianness.
     *
     * @param endianness The endian (Big or Little) to use
     * @return a long
     * @throws BufferException If this would cause an underflow (less than 8 bytes available)
     */
    long readUInt64(Endian endianness) throws BufferException;

    /**
     * Read a long from the buffer using the buffer's endianness.
     *
     * @return a long
     * @throws BufferException If this would cause an underflow (less than 8 bytes available)
     */
    long readLong() throws BufferException;

    /**
     * Read a long from the buffer using the specified endianness.
     *
     * @param endianness The endian (Big or Little) to use
     * @return a long
     * @throws BufferException If this would cause an underflow (less than 8 bytes available)
     */
    long readLong(Endian endianness) throws BufferException;

    /**
     * Read a string in the specified encoding.
     * <p/>
     * If the encoding is UTF-16, the buffer's endianness is used to determine the correct byte order.
     *
     * @param encoding The charset name to use.
     * @throws BufferException             If reading this string would cause an underflow
     * @throws UnsupportedCharsetException If the charset specified is not supported by the buffer.
     */
    String readString(String encoding, int length) throws BufferException;

    /**
     * Read a string in the specified encoding.
     * <p/>
     * If the charset is UTF-16, the buffer's endianness is used to determine the correct byte order.
     *
     * @param charset The charset to use.
     * @throws BufferException             If reading this string would cause an underflow
     * @throws UnsupportedCharsetException If the charset specified is not supported by the buffer.
     */
    String readString(Charset charset, int length) throws BufferException;

}
