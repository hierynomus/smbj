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

import java.math.BigInteger;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;

public class ShareInfo {

	private final long totalAllocationUnits;
	private final long callerAvailableAllocationUnits;
	private final long actualAvailableAllocationUnits;
	private final int sectorsPerAllocationUnit;
	private final int bytesPerSector;
	
	private final long totalSpace;
	private final long callerFreeSpace;
	private final long actualFreeSpace;
	
	private final static BigInteger MAX_VALUE = BigInteger.valueOf(Long.MAX_VALUE);
	
	ShareInfo(long totalAllocationUnits, long callerAvailableAllocationUnits,
			long actualAvailableAllocationUnits, int sectorsPerAllocationUnit, int bytesPerSector) {
		this.totalAllocationUnits = totalAllocationUnits;
		this.callerAvailableAllocationUnits = callerAvailableAllocationUnits;
		this.actualAvailableAllocationUnits = actualAvailableAllocationUnits;
		this.sectorsPerAllocationUnit = sectorsPerAllocationUnit;
		this.bytesPerSector = bytesPerSector;

		// Using BigInteger to check for overflows...
		BigInteger bytesPerAllocationUnit = BigInteger.valueOf(sectorsPerAllocationUnit).multiply(BigInteger.valueOf(bytesPerSector));
		assert bytesPerAllocationUnit.compareTo(MAX_VALUE) <= 0;
		
		BigInteger totalSpace = BigInteger.valueOf(totalAllocationUnits).multiply(bytesPerAllocationUnit);
		assert totalSpace.compareTo(MAX_VALUE) <= 0;
		
		BigInteger callerFreeSpace = BigInteger.valueOf(callerAvailableAllocationUnits).multiply(bytesPerAllocationUnit);
		assert callerFreeSpace.compareTo(MAX_VALUE) <= 0;
		
		BigInteger actualFreeSpace = BigInteger.valueOf(actualAvailableAllocationUnits).multiply(bytesPerAllocationUnit);
		assert actualFreeSpace.compareTo(MAX_VALUE) <= 0;
		
		this.totalSpace = totalSpace.longValue();
		this.callerFreeSpace = callerFreeSpace.longValue();
		this.actualFreeSpace = actualFreeSpace.longValue();
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
	
	public int getSectorsPerAllocationUnit() {
		return sectorsPerAllocationUnit;
	}
	
	public int getBytesPerSector() {
		return bytesPerSector;
	}
	
	public static ShareInfo parseFsFullSizeInformation(Buffer.PlainBuffer response) throws BufferException {
		long totalAllocationUnits = response.readUInt64();
		long callerAvailableAllocationUnits = response.readUInt64();
		long actualAvailableAllocationUnits = response.readUInt64();
		long sectorsPerAllocationUnit = response.readUInt32();
		long bytesPerSector = response.readUInt32();
		
		ShareInfo fsInfo = new ShareInfo(totalAllocationUnits, callerAvailableAllocationUnits,
				actualAvailableAllocationUnits, (int)sectorsPerAllocationUnit, (int)bytesPerSector);
		
		return fsInfo;
	}
}
