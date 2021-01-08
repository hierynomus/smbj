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
package com.hierynomus.security.jce.derivationfunction;

import org.bouncycastle.util.Arrays;

public class CounterDerivationParameters implements DerivationParameters {

    private byte[] seed;
    private byte[] fixedCounterSuffix;
    private int counterLength;

    public CounterDerivationParameters(byte[] seed, byte[] fixedCounterSuffix, int counterLength) {

        if (seed == null || seed.length == 0) {
            throw new IllegalArgumentException("Missing Seed for KDF");
        }
        this.seed = Arrays.clone(seed);

        if (fixedCounterSuffix == null) {
            this.fixedCounterSuffix = new byte[0];
        } else {
            this.fixedCounterSuffix = Arrays.clone(fixedCounterSuffix);
        }

        this.counterLength = counterLength;
    }

    public byte[] getSeed() {
        return seed;
    }

    public byte[] getFixedCounterSuffix() {
        return fixedCounterSuffix;
    }

    public int getCounterLength() {
        return counterLength;
    }
}
