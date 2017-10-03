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

import com.hierynomus.ntlm.messages.WindowsVersion;

public class AuthenticateResponse {
    private byte[] negToken;
    private byte[] signingKey;
    private WindowsVersion windowsVersion;

    public AuthenticateResponse() {
    }

    public AuthenticateResponse(byte [] negToken) {
        this.negToken = negToken;
    }

    public WindowsVersion getWindowsVersion() {
        return windowsVersion;
    }

    public void setWindowsVersion(WindowsVersion windowsVersion) {
        this.windowsVersion = windowsVersion;
    }

    public byte[] getNegToken() {
        return negToken;
    }

    public void setNegToken(byte[] negToken) {
        this.negToken = negToken;
    }

    public byte[] getSigningKey() {
        return signingKey;
    }

    public void setSigningKey(byte[] signingKey) {
        this.signingKey = signingKey;
    }
}
