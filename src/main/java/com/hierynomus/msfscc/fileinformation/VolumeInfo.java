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

import com.hierynomus.msdtyp.FileTime;
import com.hierynomus.msdtyp.MsDataTypes;
import com.hierynomus.protocol.commons.Charsets;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;

public class VolumeInfo {

    private final FileTime volumeCreationTime;

    private final int volumeSerialNumber;

    private final boolean supportsObjects;

    private final String volumeLabel;

    /**
     * [MS-SMB2] 2.2.38 SMB2 QUERY_INFO Response, SMB2_0_INFO_FILESYSTEM/FileFsVolumeInformation
     * <p>
     * [MS-FSCC] 2.5.9 FileFsVolumeInformation for SMB2
     */
    public static VolumeInfo parseFileFsVolumeInformation(Buffer.PlainBuffer buffer) throws BufferException {
        final FileTime volumeCreationTime = MsDataTypes.readFileTime(buffer);
        final int volumeSerialNumber = buffer.readUInt32AsInt();
        long nameLen = buffer.readUInt32();
        final boolean supportsObjects = buffer.readBoolean();
        buffer.skip(1);
        final String volumeLabel = buffer.readString(Charsets.UTF_16LE, (int) nameLen / 2);

        return new VolumeInfo(volumeCreationTime,volumeSerialNumber,supportsObjects, volumeLabel);
    }

    VolumeInfo(FileTime volumeCreationTime, int volumeSerialNumber, boolean supportsObjects, String volumeLabel) {
        this.volumeCreationTime = volumeCreationTime;
        this.volumeSerialNumber = volumeSerialNumber;
        this.supportsObjects = supportsObjects;
        this.volumeLabel = volumeLabel;
    }

    public FileTime getVolumeCreationTime() {
        return volumeCreationTime;
    }

    public int getVolumeSerialNumber() {
        return volumeSerialNumber;
    }

    public boolean isSupportsObjects() {
        return supportsObjects;
    }

    public String getVolumeLabel() {
        return volumeLabel;
    }

    @Override
    public String toString() {
        return "VolumeInfo{" +
            "volumeCreationTime=" + volumeCreationTime +
            ", volumeSerialNumber=" + volumeSerialNumber +
            ", supportsObjects=" + supportsObjects +
            ", volumeLabel='" + volumeLabel + '\'' +
            '}';
    }
}
