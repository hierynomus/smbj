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
package com.hierynomus.ntlm;

import java.security.SecureRandom;
import java.util.Random;

import com.hierynomus.ntlm.messages.WindowsVersion;
import com.hierynomus.ntlm.messages.WindowsVersion.NtlmRevisionCurrent;
import com.hierynomus.ntlm.messages.WindowsVersion.ProductMajorVersion;
import com.hierynomus.ntlm.messages.WindowsVersion.ProductMinorVersion;

public class NtlmConfig {
    private WindowsVersion windowsVersion;
    private String workstationName;
    private boolean integrity;
    private boolean omitVersion;
    private byte[] machineID;

    public static NtlmConfig defaultConfig() {
        return builder(new SecureRandom()).build();
    }

    public static Builder builder(Random r) {
        return new Builder(r);
    }

    public static Builder builder(NtlmConfig baseConfig) {
        return new Builder(baseConfig);
    }

    private NtlmConfig() {
    }

    private NtlmConfig(NtlmConfig other) {
        this.windowsVersion = other.windowsVersion;
        this.workstationName = other.workstationName;
        this.integrity = other.integrity;
        this.omitVersion = other.omitVersion;
        this.machineID = other.machineID;
    }

    public WindowsVersion getWindowsVersion() {
        return windowsVersion;
    }

    public String getWorkstationName() {
        return workstationName;
    }

    public boolean isIntegrityEnabled() {
        return integrity;
    }

    public boolean isOmitVersion() {
        return omitVersion;
    }

    public byte[] getMachineID() {
        return machineID;
    }

    public static class Builder {
        private NtlmConfig config;

        public Builder(Random r) {
            config = new NtlmConfig();
            config.windowsVersion = new WindowsVersion(ProductMajorVersion.WINDOWS_MAJOR_VERSION_6,
                    ProductMinorVersion.WINDOWS_MINOR_VERSION_1, 7600, NtlmRevisionCurrent.NTLMSSP_REVISION_W2K3);
            config.integrity = true;
            config.omitVersion = false;
            config.machineID = new byte[32];
            r.nextBytes(config.machineID);
        }

        public Builder(NtlmConfig baseConfig) {
            config = new NtlmConfig(baseConfig);
        }

        public Builder withWindowsVersion(WindowsVersion windowsVersion) {
            config.windowsVersion = windowsVersion;
            return this;
        }

        public Builder withWorkstationName(String workstationName) {
            config.workstationName = workstationName;
            return this;
        }

        public Builder withIntegrity(boolean integrity) {
            config.integrity = integrity;
            return this;
        }

        public Builder withOmitVersion(boolean omitVersion) {
            config.omitVersion = omitVersion;
            return this;
        }

        public Builder withMachineID(byte[] machineID) {
            if (machineID == null) {
                throw new IllegalArgumentException("MachineID must not be null");
            }
            if (machineID.length != 32) {
                throw new IllegalArgumentException("MachineID must be 32 bytes");
            }
            config.machineID = machineID;
            return this;
        }

        public NtlmConfig build() {
            return new NtlmConfig(config);
        }
    }
}
