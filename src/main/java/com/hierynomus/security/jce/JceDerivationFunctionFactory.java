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

import com.hierynomus.protocol.commons.Factory;
import com.hierynomus.security.DerivationFunction;
import com.hierynomus.security.jce.derivationfunction.KDFCounterHMacSHA256;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class JceDerivationFunctionFactory {
    private static final Map<String, Factory<DerivationFunction>> lookup = new HashMap<>();

    static {
        lookup.put("KDF/Counter/HMACSHA256", new Factory<DerivationFunction>() {
            @Override
            public DerivationFunction create() {
                try {
                    return new KDFCounterHMacSHA256();
                } catch(NoSuchAlgorithmException ex) {
                    return null;
                }
            }
        });
    }

    public static DerivationFunction create(String name) {
        Factory<DerivationFunction> derivationFunctionFactory = lookup.get(name);
        if (derivationFunctionFactory == null) {
            throw new IllegalArgumentException("Unknown DerivationFunction " + name);
        }
        DerivationFunction func = derivationFunctionFactory.create();
        if (func == null) {
            throw new IllegalArgumentException("DerivationFunction " + name + " not supported!");
        }
        return func;
    }
}
