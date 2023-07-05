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
package com.hierynomus.smbj.auth;

import java.util.Set;

import com.hierynomus.ntlm.messages.NtlmNegotiateFlag;
import com.hierynomus.ntlm.messages.WindowsVersion;
import com.hierynomus.spnego.SpnegoToken;

public class AuthenticateResponse {
    private SpnegoToken negToken;
    private byte[] sessionKey;
    private WindowsVersion windowsVersion;
    private String netBiosName;
    private Set<NtlmNegotiateFlag> negotiateFlags;

    public AuthenticateResponse() {
    }

    public AuthenticateResponse(SpnegoToken negToken) {
        this.negToken = negToken;
    }

    public WindowsVersion getWindowsVersion() {
        return windowsVersion;
    }

    public void setWindowsVersion(WindowsVersion windowsVersion) {
        this.windowsVersion = windowsVersion;
    }

    public SpnegoToken getNegToken() {
        return negToken;
    }

    public void setNegToken(SpnegoToken negToken) {
        this.negToken = negToken;
    }

    public byte[] getSessionKey() {
        return sessionKey;
    }

    public void setSessionKey(byte[] sessionKey) {
        this.sessionKey = sessionKey;
    }

    public String getNetBiosName() {
        return netBiosName;
    }

    public void setNetBiosName(String netBiosName) {
        this.netBiosName = netBiosName;
    }

    public Set<NtlmNegotiateFlag> getNegotiateFlags() {
        return negotiateFlags;
    }

    public void setNegotiateFlags(Set<NtlmNegotiateFlag> negotiateFlags) {
        this.negotiateFlags = negotiateFlags;
    }
}
