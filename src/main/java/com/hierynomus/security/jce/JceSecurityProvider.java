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
package com.hierynomus.security.jce;

import com.hierynomus.security.*;
import com.hierynomus.security.SecurityException;

import java.security.Provider;

public class JceSecurityProvider implements SecurityProvider {
    private final Provider jceProvider;
    private final String providerName;

    public JceSecurityProvider() {
        jceProvider = null;
        providerName = null;
    }

    public JceSecurityProvider(String providerName) {
        this.providerName = providerName;
        this.jceProvider = null;
    }

    public JceSecurityProvider(Provider provider) {
        this.providerName = null;
        this.jceProvider = provider;
    }

    @Override
    public MessageDigest getDigest(String name) throws SecurityException {
        return new JceMessageDigest(name, jceProvider, providerName);
    }

    @Override
    public Mac getMac(String name) throws SecurityException {
        return new JceMac(name, jceProvider, providerName);
    }

    @Override
    public Cipher getCipher(String name) throws SecurityException {
        return new JceCipher(name, jceProvider, providerName);
    }

    @Override
    public AEADBlockCipher getAEADBlockCipher(String name) throws SecurityException{
        return new JceAEADCipher(name, jceProvider, providerName);
    }

    @Override
    public DerivationFunction getDerivationFunction(String name) throws SecurityException {
        throw new UnsupportedOperationException("Key Derivation Function is currently only supported when using the BCSecurityProvider. Please configure: `SmbConfig.withSecurityProvider(new BCSecurityProvider())` to use SMB3 support.");
    }
}
