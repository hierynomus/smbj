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

import com.hierynomus.security.AEADBlockCipher;
import com.hierynomus.security.Cipher.CryptMode;
import com.hierynomus.security.SecurityException;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class JceAEADCipher implements AEADBlockCipher {
    private javax.crypto.Cipher cipher;

    JceAEADCipher(String name, Provider jceProvider, String providerName) throws SecurityException {
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
    public void init(CryptMode cryptMode, byte[] bytes, GCMParameterSpec gcmParameterSpec) throws SecurityException {
        try {
            if (CryptMode.DECRYPT == cryptMode) {
                cipher.init(javax.crypto.Cipher.DECRYPT_MODE, new SecretKeySpec(bytes, cipher.getAlgorithm().split("/")[0]), gcmParameterSpec);
            } else {
                cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new SecretKeySpec(bytes, cipher.getAlgorithm().split("/")[0]), gcmParameterSpec);
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new SecurityException(e);
        }
    }

    @Override
    public void updateAAD(byte[] aad, int aadOffset, int aadLength) throws SecurityException {
        cipher.updateAAD(aad, aadOffset, aadLength);
    }

    @Override
    public byte[] update(byte[] in, int inOffset, int inLength) throws SecurityException {
        return cipher.update(in, inOffset, inLength);
    }

    @Override
    public byte[] doFinal(byte[] in, int inOffset, int inLength) throws SecurityException {
        try {
            return cipher.doFinal(in, inOffset, inLength);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new SecurityException(e);
        }
    }

    @Override
    public void reset() {
        // no-op
    }
}
