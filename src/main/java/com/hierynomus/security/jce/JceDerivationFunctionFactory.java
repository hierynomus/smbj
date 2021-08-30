package com.hierynomus.security.jce;

import com.hierynomus.protocol.commons.Factory;
import com.hierynomus.security.DerivationFunction;
import com.hierynomus.security.SecurityException;
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
