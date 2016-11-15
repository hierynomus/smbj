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

public interface OutputBuffer<B extends OutputBuffer<B>> extends RawOutputBuffer<B> {
    /**
     * Writes a uint16 integer in the buffer's endianness.
     *
     * @param uint16
     * @return this
     */
    OutputBuffer<B> putUInt16(int uint16);

    /**
     * Writes a uint16 integer in the specified endianness.
     *
     * @param uint16
     * @param endianness The endian (Big or Little) to use
     * @return this
     */
    OutputBuffer<B> putUInt16(int uint16, Endian endianness);

    /**
     * Writes a uint24 integer in the buffer's endianness.
     *
     * @param uint24
     * @return this
     */
    OutputBuffer<B> putUInt24(int uint24);

    /**
     * Writes a uint24 integer in the specified endianness.
     *
     * @param uint24
     * @param endianness The endian (Big or Little) to use
     * @return this
     */
    OutputBuffer<B> putUInt24(int uint24, Endian endianness);

    /**
     * Writes a uint32 integer in the buffer's endianness.
     *
     * @param uint32
     * @return this
     */
    OutputBuffer<B> putUInt32(long uint32);

    /**
     * Writes a uint32 integer in the specified endianness.
     *
     * @param uint32
     * @param endianness The endian (Big or Little) to use
     * @return this
     */
    OutputBuffer<B> putUInt32(long uint32, Endian endianness);

    /**
     * Writes a uint64 integer in the buffer's endianness.
     *
     * @param uint64
     * @return this
     */
    OutputBuffer<B> putUInt64(long uint64);

    /**
     * Writes a uint64 integer in the specified endianness.
     *
     * @param uint64
     * @param endianness The endian (Big or Little) to use
     * @return this
     */
    OutputBuffer<B> putUInt64(long uint64, Endian endianness);

    /**
     * Writes a long in the buffer's endianness.
     * <p>
     * Note: unlike a uint64, a long can be <em>negative.</em>
     *
     * @param longVal
     * @return this
     */
    OutputBuffer<B> putLong(long longVal);

    /**
     * Writes a long in the specified endianness.
     * <p>
     * Note: unlike a uint64, a long can be <em>negative</em> or <em>overflowed.</em>
     *
     * @param longVal
     * @return this
     */
    OutputBuffer<B> putLong(long longVal, Endian endianness);

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
    OutputBuffer<B> putString(String string, Charset charset);
}
