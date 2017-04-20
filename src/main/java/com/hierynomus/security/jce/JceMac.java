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

import com.hierynomus.security.Mac;
import com.hierynomus.security.SecurityException;

import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

public class JceMac implements Mac {
    private final String algorithm;
    private javax.crypto.Mac mac;

    public JceMac(String algorithm, Provider jceProvider, String providerName) throws SecurityException {
        this.algorithm = algorithm;
        try {
            if (jceProvider != null) {
                mac = javax.crypto.Mac.getInstance(algorithm, jceProvider);
            } else if (providerName != null) {
                mac = javax.crypto.Mac.getInstance(algorithm, providerName);
            } else {
                mac = javax.crypto.Mac.getInstance(algorithm);
            }
        } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
            throw new SecurityException(e);
        }
    }

    @Override
    public void init(byte[] key) throws SecurityException {
        try {
            mac.init(new SecretKeySpec(key, algorithm));
        } catch (InvalidKeyException e) {
            throw new SecurityException(e);
        }
    }

    @Override
    public void update(byte b) {
        mac.update(b);
    }

    @Override
    public void update(byte[] array) {
        mac.update(array);
    }

    @Override
    public void update(byte[] array, int offset, int length) {
        mac.update(array, offset, length);
    }

    @Override
    public byte[] doFinal() {
        return mac.doFinal();
    }

    @Override
    public void reset() {
        mac.reset();
    }
}
