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
package com.hierynomus.ntlm.messages;

import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;

/**
 * [MS-NLMP].pdf 2.2.2.10 VERSION
 */
public class WindowsVersion {

    enum ProductMajorVersion implements EnumWithValue<ProductMajorVersion> {
        WINDOWS_MAJOR_VERSION_5(0x05),
        WINDOWS_MAJOR_VERSION_6(0x06),
        WINDOWS_MAJOR_VERSION_10(0x0A);

        private long value;

        ProductMajorVersion(int value) {
            this.value = value;
        }

        @Override
        public long getValue() {
            return value;
        }
    }

    enum ProductMinorVersion implements EnumWithValue<ProductMinorVersion> {
        WINDOWS_MINOR_VERSION_0(0x00),
        WINDOWS_MINOR_VERSION_1(0x01),
        WINDOWS_MINOR_VERSION_2(0x02),
        WINDOWS_MINOR_VERSION_3(0x03);
        private long value;

        ProductMinorVersion(int value) {
            this.value = value;
        }

        @Override
        public long getValue() {
            return value;
        }
    }

    enum NtlmRevisionCurrent implements EnumWithValue<NtlmRevisionCurrent> {
        NTLMSSP_REVISION_W2K3(0x0F);

        private long value;

        NtlmRevisionCurrent(int value) {
            this.value = value;
        }

        @Override
        public long getValue() {
            return value;
        }
    }

    private ProductMajorVersion majorVersion;
    private ProductMinorVersion minorVersion;
    private int productBuild;
    private NtlmRevisionCurrent ntlmRevision;

    WindowsVersion() {
    }

    WindowsVersion readFrom(Buffer.PlainBuffer buffer) {
        this.majorVersion = EnumWithValue.EnumUtils.valueOf(buffer.readByte(), ProductMajorVersion.class, null); // ProductMajorVersion (1 byte)
        this.minorVersion = EnumWithValue.EnumUtils.valueOf(buffer.readByte(), ProductMinorVersion.class, null); // ProductMinorVersion (1 byte)
        this.productBuild = buffer.readUInt16(); // ProductBuild (2 bytes)
        buffer.skip(3); // Reserved (3 bytes)
        this.ntlmRevision = EnumWithValue.EnumUtils.valueOf(buffer.readByte(), NtlmRevisionCurrent.class, null); // NTLMRevisionCurrent (1 byte)
        return this;
    }

    @Override
    public String toString() {
        return String.format("WindowsVersion[%s, %s, %d, %s]", majorVersion, minorVersion, productBuild, ntlmRevision);
    }
}
