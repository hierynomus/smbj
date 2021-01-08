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
import com.hierynomus.security.DerivationFunction;
import com.hierynomus.security.jce.derivationfunction.CounterDerivationParameters;
import com.hierynomus.security.jce.derivationfunction.DerivationParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KDFCounterParameters;

import java.util.HashMap;
import java.util.Map;

public class BCDerivationFunctionFactory {
    private static final Map<String, Factory<DerivationFunction>> lookup = new HashMap<>();

    static {
        lookup.put("KDF/Counter/HMACSHA256", new Factory<DerivationFunction>() {
            @Override
            public DerivationFunction create() {
                return new BCDerivationFunction(new KDFCounterBytesGenerator(new HMac(new SHA256Digest()))) {
                    @Override
                    protected org.bouncycastle.crypto.DerivationParameters createParams(DerivationParameters in) {
                        if (!(in instanceof CounterDerivationParameters)) {
                            throw new IllegalArgumentException("Parameters should be a CounterDerivationParameters");
                        }

                        CounterDerivationParameters p = (CounterDerivationParameters) in;
                        return new KDFCounterParameters(p.getSeed(), p.getFixedCounterSuffix(), p.getCounterLength());
                    }
                };
            }
        });
    }

    public static DerivationFunction create(String name) {
        Factory<DerivationFunction> derivationFunctionFactory = lookup.get(name);
        if (derivationFunctionFactory == null) {
            throw new IllegalArgumentException("Unknown DerivationFunction " + name);
        }
        return derivationFunctionFactory.create();
    }

    static abstract class BCDerivationFunction implements DerivationFunction {
        private final org.bouncycastle.crypto.DerivationFunction function;

        public BCDerivationFunction(org.bouncycastle.crypto.DerivationFunction function) {
            this.function = function;
        }

        @Override
        public void init(DerivationParameters parameters) {
            this.function.init(createParams(parameters));
        }

        @Override
        public int generateBytes(byte[] out, int outOff, int len) {
            return function.generateBytes(out, outOff, len);
        }

        protected abstract org.bouncycastle.crypto.DerivationParameters createParams(DerivationParameters in);
    }
}
