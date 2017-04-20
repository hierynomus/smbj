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

import com.hierynomus.security.Cipher;
import com.hierynomus.security.SecurityException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

public class JceCipher implements Cipher {
    private javax.crypto.Cipher cipher;

    JceCipher(String name, Provider jceProvider, String providerName) throws SecurityException {
        try {
            if (jceProvider != null) {
                this.cipher = javax.crypto.Cipher.getInstance(name, jceProvider);
            } else if (providerName != null) {
                this.cipher = javax.crypto.Cipher.getInstance(name, providerName);
            } else {
                this.cipher = javax.crypto.Cipher.getInstance(name);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
            throw new SecurityException(e);
        }
    }

    @Override
    public void init(CryptMode cryptMode, byte[] bytes) throws SecurityException {
        try {
            if (CryptMode.DECRYPT == cryptMode) {
                cipher.init(javax.crypto.Cipher.DECRYPT_MODE, new SecretKeySpec(bytes, cipher.getAlgorithm().split("/")[0]));
            } else {
                cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new SecretKeySpec(bytes, cipher.getAlgorithm().split("/")[0]));
            }
        } catch (InvalidKeyException e) {
            throw new SecurityException(e);
        }
    }

    @Override
    public int update(byte[] in, int inOff, int bytes, byte[] out, int outOff) throws SecurityException {
        try {
            return cipher.update(in, inOff, bytes, out, outOff);
        } catch (ShortBufferException e) {
            throw new SecurityException(e);
        }
    }

    @Override
    public int doFinal(byte[] out, int outOff) throws SecurityException {
        try {
            return cipher.doFinal(out, outOff);
        } catch (BadPaddingException | IllegalBlockSizeException | ShortBufferException e) {
            throw new SecurityException(e);
        }
    }

    @Override
    public void reset() {
        // no-op
    }
}
