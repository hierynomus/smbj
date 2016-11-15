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

public interface RawOutputBuffer<B extends RawOutputBuffer<B>> {
//    /**
//     * Ensure that there is at least <code>capacity</code> bytes available in the buffer for writing.
//     * This call enlarges the buffer if there is less capacity than requested.
//     *
//     * @param capacity The capacity required/
//     */
//    void ensureCapacity(int capacity);

    /**
     * Returns the current writing position of this buffer.
     *
     * @return The current writing position.
     */
    int wpos();

    /**
     * Clears the buffer.
     */
    void clear();


    /**
     * Writes a single byte into this buffer
     *
     * @param b
     * @return this
     */
    RawOutputBuffer<B> putByte(byte b);

    /**
     * Write the bytes of the passed byte array into this buffer.
     *
     * @param buf The array of bytes to write.
     * @return this.
     */
    RawOutputBuffer<B> putRawBytes(byte[] buf);

    /**
     * Write the bytes of the passed byte array into this buffer, starting at offset, and writing length bytes.
     *
     * @param buf    The array of bytes to write
     * @param offset The offset at which to start reading from the passed array
     * @param length The number of bytes to write from the passed array
     * @return this.
     */
    RawOutputBuffer<B> putRawBytes(byte[] buf, int offset, int length);
}
