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
package com.hierynomus.msfscc;

import com.hierynomus.protocol.commons.EnumWithValue;

/**
 * MS-FSCC 2.5 File System Information Classes
 */
public enum FileSystemInformationClass implements EnumWithValue<FileSystemInformationClass> {

    FileFsVolumeInformation(0x01L),
    FileFsLabelInformation(0x02L),
    FileFsSizeInformation(0x03L),
    FileFsDeviceInformation(0x04L),
    FileFsAttributeInformation(0x05L),
    FileFsControlInformation(0x06L),
    FileFsFullSizeInformation(0x07L),
    FileFsObjectIdInformation(0x08L),
    FileFsDriverPathInformation(0x09L),
    FileFsVolumeFlagsInformation(0x0AL),
    FileFsSectorSizeInformation(0x0BL);

    private long value;

    FileSystemInformationClass(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
