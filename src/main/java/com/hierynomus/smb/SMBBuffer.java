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
package com.hierynomus.smb;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class SMBBuffer extends Buffer<SMBBuffer> {
    private static final byte[] RESERVED_2 = new byte[]{0x0, 0x0};
    private static final byte[] RESERVED_4 = new byte[]{0x0, 0x0, 0x0, 0x0};

    public SMBBuffer() {
        super(Endian.LE);
    }

    public SMBBuffer(byte[] data) {
        super(data, Endian.LE);
    }

    /**
     * Puts '0' bytes for reserved parts of messages/headers
     *
     * @param length The length of the reserved space.
     * @return this
     */
    public Buffer<SMBBuffer> putReserved(int length) {
        byte[] nullBytes = new byte[length];
        Arrays.fill(nullBytes, (byte) 0);
        putRawBytes(nullBytes);
        return this;
    }

    /**
     * Shortcut method for putting 1 reserved byte in the buffer.
     *
     * @return this
     */
    public Buffer<SMBBuffer> putReserved1() {
        putByte((byte) 0);
        return this;
    }

    /**
     * Shortcut method for putting 2 reserved bytes in the buffer.
     *
     * @return this
     */
    public Buffer<SMBBuffer> putReserved2() {
        putRawBytes(RESERVED_2);
        return this;
    }

    /**
     * Shortcut method for putting 4 reserved bytes in the buffer.
     *
     * @return this
     */
    public Buffer<SMBBuffer> putReserved4() {
        putRawBytes(RESERVED_4);
        return this;
    }

    /**
     * [MS-SMB2].pdf 2.2 Message Syntax
     *
     * @param string The string value to write
     * @return this
     */
    public Buffer<SMBBuffer> putString(String string) {
        return putString(string, StandardCharsets.UTF_16);
    }

    /**
     * [MS-SMB2].pdf 2.2 Message Syntax
     *
     * @param string the string of which to write the length
     * @return this
     */
    public Buffer<SMBBuffer> putStringLengthUInt16(String string) {
        if (string == null) {
            return putUInt16(0);
        }
        return putUInt16(string.length() * 2);
    }
}
