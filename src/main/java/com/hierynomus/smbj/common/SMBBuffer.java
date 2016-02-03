/*
 * Copyright (C)2016 - Jeroen van Erp <jeroen@hierynomus.com>
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
package com.hierynomus.smbj.common;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;

import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

public class SMBBuffer extends Buffer<SMBBuffer> {
    private static final byte[] RESERVED_4 = new byte[]{0x0, 0x0, 0x0, 0x0};
    public static final int NANO100_TO_MILLI = 10000;
    public static final long WINDOWS_TO_UNIX_EPOCH = 0x19DB1DED53E8000L;

    public SMBBuffer() {
        super(Endian.LE);
    }

    public SMBBuffer(byte[] data) {
        super(data, Endian.LE);
    }

    /**
     * [MS-DTYP].pdf 2.3.4.2 GUID Packet representation
     *
     * @param guid The GUID to write.
     * @return this
     */
    public Buffer<SMBBuffer> putGuid(UUID guid) {
        long leastSignificantBits = guid.getLeastSignificantBits();
        long mostSignificantBits = guid.getMostSignificantBits();
        // Unsigned shifts
        putUInt32(mostSignificantBits >>> 32); // Data1 (4 bytes)
        putUInt16((int) ((mostSignificantBits >>> 16) & 0xFFFF)); // Data2 (2 bytes)
        putUInt16((int) (mostSignificantBits & 0xFFFF)); // Data 3 (2 bytes)
        // For some weird reason the correct way of reading/writing the last part is BigEndian, thanks MS.
        // This could be due to the fact that the Data4 section is regarded as an opaque byte sequence, so no
        // endian translation is applied, unlike the Data1/2/3 sections which are regarded as unsigned long/short/short
        putLong(leastSignificantBits, Endian.BE);
        return this;
    }


    /**
     * [MS-DTYP].pdf 2.3.4.2 GUID Packet representation
     *
     * @return The GUID read from the buffer
     * @throws BufferException If an underflow occurs by reading the GUID (less than 16 bytes available).
     */
    public UUID readGuid() throws BufferException {
        long mostSigBits = readUInt32();
        mostSigBits <<= 16;
        mostSigBits |= readUInt16();
        mostSigBits <<= 16;
        mostSigBits |= readUInt16();
        // For some weird reason the correct way of reading/writing the last part is BigEndian, thanks MS.
        // This could be due to the fact that the Data4 section is regarded as an opaque byte sequence, so no
        // endian translation is applied, unlike the Data1/2/3 sections which are regarded as unsigned long/short/short
        long leastSigBits = readLong(Endian.BE);
        return new UUID(mostSigBits, leastSigBits);
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
     * Shortcut method for putting 4 reserved bytes in the buffer.
     *
     * @return this
     */
    public Buffer<SMBBuffer> putReserved4() {
        putRawBytes(RESERVED_4);
        return this;
    }

    /**
     * [MS-DTYP].pdf 2.3.3 FILETIME
     *
     * @return a Date converted from the Windows FILETIME stored in the buffer
     * @throws BufferException If an underflow occurs by reading the FILETIME (less than 8 bytes available).
     */
    public Date readDate() throws BufferException {
        long lowOrder = readUInt32();
        long highOrder = readUInt32();
        long windowsTimeStamp = (highOrder << 32) | lowOrder;
        return new Date((windowsTimeStamp - WINDOWS_TO_UNIX_EPOCH) / NANO100_TO_MILLI);
    }

    /**
     * [MS-SMB2].pdf 2.2 Message Syntax
     *
     * @param string The string value to write
     * @return this
     */
    public Buffer<SMBBuffer> putString(String string) {
        return putString(string, Charset.forName("UTF-16"));
    }
}
