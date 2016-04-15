/*
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
package com.hierynomus.smbj.smb2;

import com.hierynomus.protocol.commons.EnumWithValue;

/**
 * SMB2 2.2.33 SMB2 QUERY_DIRECTORY - FileInformationClass
 * MS-FSCC 2.4 File Information Classes
 */
public enum SMB2FileInformationClass implements EnumWithValue<SMB2FileInformationClass> {

    FileDirectoryInformation(0x01),
    FileFullDirectoryInformation(0x02),
    FileIdFullDirectoryInformation(0x26),
    FileBothDirectoryInformation(0x03),
    FileIdBothDirectoryInformation(0x25),
    FileNamesInformation(0x0C);

    private long value;

    SMB2FileInformationClass(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
