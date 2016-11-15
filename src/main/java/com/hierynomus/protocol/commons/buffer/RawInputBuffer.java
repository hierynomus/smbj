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

public interface RawInputBuffer {
//    /**
//     * Ensure that there are at least <code>a</code> bytes available for reading from this buffer.
//     *
//     * @param a The number of bytes to ensure are at least available
//     * @throws BufferException If there are less than <code>a</code> bytes available
//     */
//    void ensureAvailable(int a) throws BufferException;

    /**
     * Returns the number of bytes still available to read from the buffer.
     *
     * @return The number of bytes available from the buffer.
     */
    int available();

    /**
     * Returns the current reading position of the buffer.
     *
     * @return The current reading position
     */
    int rpos();

    /**
     * Set the current reading position.
     *
     * @param rpos The new reading position
     */
    void rpos(int rpos);

    /**
     * Read a byte from the buffer
     *
     * @return the byte read
     */
    byte readByte() throws BufferException;

    /**
     * Read <code>length</code> raw bytes from the buffer into a newly allocated byte array of length <code>length</code>.
     *
     * @param length The number of bytes to read.
     * @return a newly allocated byte array of <code>length</code> containing the read bytes.
     * @throws BufferException If the read operation would cause an underflow (less than <code>length</code> bytes available)
     */
    byte[] readRawBytes(int length) throws BufferException;

    /**
     * Read a raw byte array from the buffer into the passed byte array. Will try to read exactly the size of array bytes.
     *
     * @param buf The array to write the read bytes into
     * @throws BufferException If the read operation would cause an underflow (less bytes available than array size)
     */
    void readRawBytes(byte[] buf) throws BufferException;

    /**
     * Read a raw byte array from the buffer into the passed byte array starting at offset, and reading exactly length bytes.
     *
     * @param buf    The array to write the read bytes into
     * @param offset The offset at which to start writing into the array
     * @param length The number of bytes to read from this buffer
     * @throws BufferException If the read operation would cause an underflow (less than length bytes available)
     */
    void readRawBytes(byte[] buf, int offset, int length) throws BufferException;

    /**
     * Skip the specified number of bytes.
     *
     * @param length The number of bytes to skip
     * @throws BufferException If this would cause an underflow (less than <code>length</code>) bytes available).
     */
    void skip(int length) throws BufferException;
}
