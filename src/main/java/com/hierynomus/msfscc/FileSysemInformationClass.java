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
public enum FileSysemInformationClass implements EnumWithValue<FileSysemInformationClass> {

    FileFsVolumeInformation(0x01),
    FileFsLabelInformation(0x02),
    FileFsSizeInformation(0x03),
    FileFsDeviceInformation(0x04),
    FileFsAttributeInformation(0x05),
    FileFsControlInformation(0x06),
    FileFsFullSizeInformation(0x07),
    FileFsObjectIdInformation(0x08),
    FileFsDriverPathInformation(0x09),
    FileFsVolumeFlagsInformation(0x0A),
    FileFsSectorSizeInformation(0x0B);

    private long value;

    FileSysemInformationClass(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
