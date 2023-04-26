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

import com.hierynomus.ntlm.messages.WindowsVersion;

public class NtlmConfig {
    private WindowsVersion windowsVersion;
    private String workstationName;
    private boolean integrity;

    public static NtlmConfig defaultConfig() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    private NtlmConfig() {
    }

    private NtlmConfig(NtlmConfig other) {
        this.windowsVersion = other.windowsVersion;
        this.workstationName = other.workstationName;
        this.integrity = other.integrity;
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

    public static class Builder {
        private NtlmConfig config;

        public Builder() {
            config = new NtlmConfig();
            config.integrity = true;
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

        public NtlmConfig build() {
            return new NtlmConfig(config);
        }
    }
}
