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

import com.hierynomus.security.MessageDigest;
import com.hierynomus.security.SecurityException;
import com.hierynomus.security.jce.messagedigest.MD4;

import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

public class JceMessageDigest implements MessageDigest {
    private java.security.MessageDigest md;

    JceMessageDigest(String algorithm, Provider jceProvider, String providerName) throws SecurityException {
        try {
            if (jceProvider != null) {
                this.md = java.security.MessageDigest.getInstance(algorithm, jceProvider);
            } else if (providerName != null) {
                this.md = java.security.MessageDigest.getInstance(algorithm, providerName);
            } else {
                this.md = java.security.MessageDigest.getInstance(algorithm);
            }
        } catch (NoSuchAlgorithmException e) {
            if ("MD4".equals(algorithm)) {
                this.md = new MD4();
            } else {
                throw new SecurityException(e);
            }
        } catch (NoSuchProviderException e) {
            throw new SecurityException(e);
        }
    }

    @Override
    public void update(byte[] bytes) {
        md.update(bytes);
    }

    @Override
    public byte[] digest() {
        return md.digest();
    }

    @Override
    public void reset() {
        md.reset();
    }
}
