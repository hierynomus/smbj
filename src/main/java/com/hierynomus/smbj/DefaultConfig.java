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
package com.hierynomus.smbj;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.security.jce.JceSecurityProvider;
import com.hierynomus.smbj.auth.NtlmAuthenticator;
import com.hierynomus.smbj.auth.SpnegoAuthenticator;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.UUID;

public class DefaultConfig extends ConfigImpl {

    public DefaultConfig() {
        random = new SecureRandom();
        securityProvider = new JceSecurityProvider();
        dialects = EnumSet.of(SMB2Dialect.SMB_2_1, SMB2Dialect.SMB_2_0_2);
        clientGuid = UUID.randomUUID();
        signingRequired = false;
        registerDefaultAuthenticators();
        isDFSEnabled = false; // DFS Support is currently experimental and disabled by default.
    }

    private void registerDefaultAuthenticators() {
        authenticators = new ArrayList<>();
        // order is important.  The authenticators listed first will be selected
        authenticators.add(new SpnegoAuthenticator.Factory());
        authenticators.add(new NtlmAuthenticator.Factory());
    }
}
