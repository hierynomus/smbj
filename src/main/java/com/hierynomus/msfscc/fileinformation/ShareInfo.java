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

package com.hierynomus.msfscc.fileinformation;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.BufferException;

public class ShareInfo {
    /*
     * A 64-bit signed integer that contains the total number of allocation
     * units on the volume that are available to the user associated with the
     * calling thread. The value of this field MUST be greater than or equal to 0.
     */
    private final long totalAllocationUnits;
    /*
     * A 64-bit signed integer that contains the total number of free allocation
     * units on the volume that are available to the user associated with the
     * calling thread. The value of this field MUST be greater than or equal to 0.
     */
    private final long callerAvailableAllocationUnits;
    /*
     * A 64-bit signed integer that contains the total number of free allocation
     * units on the volume. The value of this field MUST be greater than or
     * equal to 0.
     */
    private final long actualAvailableAllocationUnits;
    /*
     * A 32-bit unsigned integer that contains the number of sectors in each
     * allocation unit.
     */
    private final long sectorsPerAllocationUnit;
    /*
     * A 32-bit unsigned integer that contains the number of bytes in each
     * sector.
     */
    private final long bytesPerSector;
    /*
     * Total space in bytes on the volume.
     */
    private final long totalSpace;
    /*
     * Free space in bytes on the volume available to the user associated with
     * the calling thread.
     */
    private final long callerFreeSpace;
    /*
     * Total free space in bytes on the volume.
     */
    private final long actualFreeSpace;

    ShareInfo(long totalAllocationUnits, long callerAvailableAllocationUnits,
              long actualAvailableAllocationUnits, long sectorsPerAllocationUnit, long bytesPerSector) {
        this.totalAllocationUnits = totalAllocationUnits;
        this.callerAvailableAllocationUnits = callerAvailableAllocationUnits;
        this.actualAvailableAllocationUnits = actualAvailableAllocationUnits;
        this.sectorsPerAllocationUnit = sectorsPerAllocationUnit;
        this.bytesPerSector = bytesPerSector;

        long bytesPerAllocationUnit = sectorsPerAllocationUnit * bytesPerSector;

        this.totalSpace = totalAllocationUnits * bytesPerAllocationUnit;
        this.callerFreeSpace = callerAvailableAllocationUnits * bytesPerAllocationUnit;
        this.actualFreeSpace = actualAvailableAllocationUnits * bytesPerAllocationUnit;
    }

    public long getFreeSpace() {
        return actualFreeSpace;
    }

    public long getCallerFreeSpace() {
        return callerFreeSpace;
    }

    public long getTotalSpace() {
        return totalSpace;
    }

    public long getTotalAllocationUnits() {
        return totalAllocationUnits;
    }

    public long getAvailableAllocationUnits() {
        return actualAvailableAllocationUnits;
    }

    public long getCallerAvailableAllocationUnits() {
        return callerAvailableAllocationUnits;
    }

    public long getSectorsPerAllocationUnit() {
        return sectorsPerAllocationUnit;
    }

    public long getBytesPerSector() {
        return bytesPerSector;
    }

    /**
     * [MS-SMB2] 2.2.38 SMB2 QUERY_INFO Response, SMB2_0_INFO_FILESYSTEM/FileFsFullSizeInformation
     * <p>
     * [MS-FSCC] 2.5.4 FileFsFullSizeInformation for SMB2
     */
    public static ShareInfo parseFsFullSizeInformation(Buffer.PlainBuffer response) throws BufferException {

        long totalAllocationUnits = response.readLong();            // TotalAllocationUnits
        long callerAvailableAllocationUnits = response.readLong();    // CallerAvailableAllocationUnits
        long actualAvailableAllocationUnits = response.readLong();    // ActualAvailableAllocationUnits
        long sectorsPerAllocationUnit = response.readUInt32();        // SectorsPerAllocationUnit
        long bytesPerSector = response.readUInt32();                // BytesPerSector

        return new ShareInfo(totalAllocationUnits, callerAvailableAllocationUnits,
            actualAvailableAllocationUnits, sectorsPerAllocationUnit, bytesPerSector);
    }
}
