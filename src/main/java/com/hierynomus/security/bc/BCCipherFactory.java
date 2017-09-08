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
import com.hierynomus.security.Cipher;
import com.hierynomus.security.SecurityException;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.HashMap;
import java.util.Map;

public class BCCipherFactory {
    private static final Map<String, Factory<Cipher>> lookup = new HashMap<>();

    static {
        lookup.put("DES/ECB/NoPadding", new Factory<Cipher>() {
            @Override
            public Cipher create() {
                return new BCBlockCipher(new BufferedBlockCipher(new DESEngine())) {
                    @Override
                    protected CipherParameters createParams(byte[] key) {
                        return new DESedeParameters(key);
                    }
                };
            }
        });
        lookup.put("RC4", new Factory<Cipher>() {
            @Override
            public Cipher create() {
                return new BCStreamCipher(new RC4Engine()) {
                    @Override
                    protected CipherParameters createParams(byte[] key) {
                        return new KeyParameter(key);
                    }
                };
            }
        });
    }

    public static Cipher create(String name) {
        Factory<Cipher> cipherFactory = lookup.get(name);
        if (cipherFactory == null) {
            throw new IllegalArgumentException("Unknown Cipher " + name);
        }
        return cipherFactory.create();
    }

    private static abstract class BCBlockCipher implements Cipher {
        private BufferedBlockCipher wrappedCipher;

        BCBlockCipher(BufferedBlockCipher bufferedBlockCipher) {
            wrappedCipher = bufferedBlockCipher;
        }

        @Override
        public void init(CryptMode cryptMode, byte[] bytes) {
            wrappedCipher.init(cryptMode == CryptMode.ENCRYPT, createParams(bytes));
        }

        @Override
        public int update(byte[] in, int inOff, int bytes, byte[] out, int outOff) throws SecurityException {
            return wrappedCipher.processBytes(in, inOff, bytes, out, outOff);
        }

        @Override
        public int doFinal(byte[] out, int outOff) throws SecurityException {
            try {
                return wrappedCipher.doFinal(out, outOff);
            } catch (InvalidCipherTextException e) {
                throw new SecurityException(e);
            }
        }

        @Override
        public void reset() {
            wrappedCipher.reset();
        }

        protected abstract CipherParameters createParams(byte[] key);
    }

    private static abstract class BCStreamCipher implements Cipher {
        private StreamCipher streamCipher;

        BCStreamCipher(StreamCipher streamCipher) {
            this.streamCipher = streamCipher;
        }

        @Override
        public void init(CryptMode cryptMode, byte[] bytes) throws SecurityException {
            streamCipher.init(cryptMode == CryptMode.ENCRYPT, createParams(bytes));
        }

        protected abstract CipherParameters createParams(byte[] key);

        @Override
        public int update(byte[] in, int inOff, int bytes, byte[] out, int outOff) throws SecurityException {
            return streamCipher.processBytes(in, inOff, bytes, out, outOff);
        }

        @Override
        public int doFinal(byte[] out, int outOff) throws SecurityException {
            streamCipher.reset();
            return 0;
        }

        @Override
        public void reset() {
            streamCipher.reset();
        }


    }

}
