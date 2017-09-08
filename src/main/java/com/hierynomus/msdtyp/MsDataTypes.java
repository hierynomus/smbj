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
package com.hierynomus.msdtyp;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;

import java.util.UUID;

/**
 * Utility class that can read and write data types from the [MS-DTYP].pdf specification document from buffers.
 */
public class MsDataTypes {

    private MsDataTypes() {
    }

    /**
     * [MS-DTYP].pdf 2.3.4.2 GUID Packet representation
     *
     * @param guid The GUID to write.
     */
    public static void putGuid(UUID guid, Buffer<?> buffer) {
        long leastSignificantBits = guid.getLeastSignificantBits();
        long mostSignificantBits = guid.getMostSignificantBits();
        // Unsigned shifts
        buffer.putUInt32(mostSignificantBits >>> 32); // Data1 (4 bytes)
        buffer.putUInt16((int) ((mostSignificantBits >>> 16) & 0xFFFF)); // Data2 (2 bytes)
        buffer.putUInt16((int) (mostSignificantBits & 0xFFFF)); // Data 3 (2 bytes)
        // For some weird reason the correct way of reading/writing the last part is BigEndian, thanks MS.
        // This could be due to the fact that the Data4 section is regarded as an opaque byte sequence, so no
        // endian translation is applied, unlike the Data1/2/3 sections which are regarded as unsigned long/short/short
        buffer.putLong(leastSignificantBits, Endian.BE);
    }

    /**
     * [MS-DTYP].pdf 2.3.4.2 GUID Packet representation
     *
     * @return The GUID read from the buffer
     * @throws Buffer.BufferException If an underflow occurs by reading the GUID (less than 16 bytes available).
     */
    public static UUID readGuid(Buffer<?> buffer) throws Buffer.BufferException {
        long mostSigBits = buffer.readUInt32();
        mostSigBits <<= 16;
        mostSigBits |= buffer.readUInt16();
        mostSigBits <<= 16;
        mostSigBits |= buffer.readUInt16();
        // For some weird reason the correct way of reading/writing the last part is BigEndian, thanks MS.
        // This could be due to the fact that the Data4 section is regarded as an opaque byte sequence, so no
        // endian translation is applied, unlike the Data1/2/3 sections which are regarded as unsigned long/short/short
        long leastSigBits = buffer.readLong(Endian.BE);
        return new UUID(mostSigBits, leastSigBits);
    }

    /**
     * [MS-DTYP].pdf 2.3.3 FILETIME
     *
     * @return a Date converted from the Windows FILETIME stored in the buffer
     * @throws Buffer.BufferException If an underflow occurs by reading the FILETIME (less than 8 bytes available).
     */
    public static FileTime readFileTime(Buffer<?> buffer) throws Buffer.BufferException {
        long lowOrder = buffer.readUInt32();
        long highOrder = buffer.readUInt32();
        long windowsTimeStamp = (highOrder << 32) | lowOrder;
        return new FileTime(windowsTimeStamp);
    }

    /**
     * [MS-DTYP].pdf 2.3.3 FILETIME
     * <p>
     * store Date into FileTime in the buffer
     */
    public static void putFileTime(FileTime fileTime, Buffer<?> buffer) {
        long timestamp = fileTime.getWindowsTimeStamp();
        buffer.putUInt32(timestamp & 0xFFFFFFFFL);
        buffer.putUInt32((timestamp >> 32) & 0xFFFFFFFFL);
    }

    /**
     * A 64-bit unsigned integer that contains the current system time, represented
     * as the number of 100 nanosecond ticks elapsed since midnight of January 1, 1601 (UTC)
     */
    public static long nowAsFileTime() {
        return FileTime.now().getWindowsTimeStamp();
    }
}
