package com.hierynomus.ntlm;

import com.hierynomus.ntlm.messages.WindowsVersion;

public class NtlmConfig {
    private WindowsVersion windowsVersion;
    private String workstationName;

    public static NtlmConfig defaultConfig() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public WindowsVersion getWindowsVersion() {
        return windowsVersion;
    }

    public String getWorkstationName() {
        return workstationName;
    }

    public static class Builder {
        private NtlmConfig config;

        public Builder withWindowsVersion(WindowsVersion windowsVersion) {
            config.windowsVersion = windowsVersion;
            return this;
        }

        public Builder withWorkstationName(String workstationName) {
            config.workstationName = workstationName;
            return this;
        }

        public NtlmConfig build() {
            return config;
        }
    }
}
