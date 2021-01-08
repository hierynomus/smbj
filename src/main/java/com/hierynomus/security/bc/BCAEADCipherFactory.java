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
package com.hierynomus.security.bc;

import com.hierynomus.protocol.commons.Factory;
import com.hierynomus.security.AEADBlockCipher;
import com.hierynomus.security.Cipher.CryptMode;
import com.hierynomus.security.SecurityException;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.GCMParameterSpec;

public class BCAEADCipherFactory {
    private static final Map<String, Factory<AEADBlockCipher>> lookup = new HashMap<>();

    static {
        lookup.put("AES/CCM/NoPadding", new Factory<AEADBlockCipher>() {
            @Override
            public AEADBlockCipher create() {
                return new BCAEADBlockCipher(new CCMBlockCipher(new AESEngine())) {
                    @Override
                    protected CipherParameters createParams(byte[] key,
                                                            GCMParameterSpec gcmParameterSpec) {
                        return new AEADParameters(
                            new KeyParameter(key),
                            gcmParameterSpec.getTLen(),
                            gcmParameterSpec.getIV()
                        );
                    }
                };
            }
        });
        lookup.put("AES/GCM/NoPadding", new Factory<AEADBlockCipher>() {
            @Override
            public AEADBlockCipher create() {
                return new BCAEADBlockCipher(new GCMBlockCipher(new AESEngine())) {
                    @Override
                    protected CipherParameters createParams(byte[] key,
                                                            GCMParameterSpec gcmParameterSpec) {
                        return new AEADParameters(
                            new KeyParameter(key),
                            gcmParameterSpec.getTLen(),
                            gcmParameterSpec.getIV()
                        );
                    }
                };
            }
        });
    }

    public static AEADBlockCipher create(String name) {
        Factory<AEADBlockCipher> cipherFactory = lookup.get(name);
        if (cipherFactory == null) {
            throw new IllegalArgumentException("Unknown AEADCipher " + name);
        }
        return cipherFactory.create();
    }

    private static abstract class BCAEADBlockCipher implements AEADBlockCipher {
        private org.bouncycastle.crypto.modes.AEADBlockCipher wrappedCipher;

        BCAEADBlockCipher(org.bouncycastle.crypto.modes.AEADBlockCipher aeadBlockCipher) {
            this.wrappedCipher = aeadBlockCipher;
        }

        @Override
        public void init(CryptMode cryptMode, byte[] bytes, GCMParameterSpec gcmParameterSpec) throws SecurityException {
            wrappedCipher.init(cryptMode == CryptMode.ENCRYPT, createParams(bytes, gcmParameterSpec));
        }

        @Override
        public void updateAAD(byte[] aad, int aadOffset, int aadLength) throws SecurityException {
            wrappedCipher.processAADBytes(aad, aadOffset, aadLength);
        }

        @Override
        public byte[] update(byte[] in, int inOffset, int inLength) throws SecurityException {
            int outputSize = wrappedCipher.getUpdateOutputSize(inLength);
            byte[] out = new byte[outputSize];
            wrappedCipher.processBytes(in, inOffset, inLength, out, 0);
            return out;
        }

        @Override
        public byte[] doFinal(byte[] in, int inOffset, int inLength) throws SecurityException {
            int outOff = 0;
            int outputSizeWithFinal = wrappedCipher.getOutputSize(inLength);
            byte[] out = new byte[outputSizeWithFinal];
            outOff += wrappedCipher.processBytes(in, inOffset, inLength, out, outOff);
            try {
                outOff += wrappedCipher.doFinal(out, outOff);
            } catch (InvalidCipherTextException e) {
                throw new SecurityException(e);
            }
            return out;
        }

        @Override
        public void reset() {
            wrappedCipher.reset();
        }

        protected abstract CipherParameters createParams(byte[] key, GCMParameterSpec gcmParameterSpec);
    }
}
