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

import com.hierynomus.security.SecurityException;
import com.hierynomus.security.jce.JceDerivationFunction;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class KDFCounterHMacSHA256 extends JceDerivationFunction {
    private Mac mac;
    private byte[] fixedSuffix;
    private int maxLength;

    public KDFCounterHMacSHA256() throws NoSuchAlgorithmException {
        mac = Mac.getInstance("HmacSHA256");
    }

    @Override
    public void init(DerivationParameters parameters) throws SecurityException {
        if (!(parameters instanceof CounterDerivationParameters)) {
            throw new IllegalArgumentException("Parameters should be a CounterDerivationParameters");
        }

        CounterDerivationParameters p = (CounterDerivationParameters) parameters;
        SecretKeySpec seed = new SecretKeySpec(p.getSeed(), "HmacSHA256");
        try {
            mac.init(seed);
        } catch(InvalidKeyException ex) {
            throw new SecurityException(ex);
        }
        this.fixedSuffix = p.getFixedCounterSuffix();
        this.maxLength = p.getCounterLength();
    }

    @Override
    public int generateBytes(byte[] out, int outOff, int len) {
        int generated = 0;
        //The number of rounds is the output length divided by the size (in bytes of the function output)
        int rounds = len/32;
        if ((len % 32) != 0) {
            //Do one more round for the odd bytes
            rounds++;
        }
        byte[] input = new byte[4];
        for (int i = 0; i < rounds; i++) {
            input[0] = (byte)((i+1) >>> 24);
            input[1] = (byte)((i+1) >>> 16);
            input[2] = (byte)((i+1) >>> 8);
            input[3] = (byte)(i+1);
            mac.update(input);
            mac.update(this.fixedSuffix);
            byte[] tmp = mac.doFinal();
            int toCopy = tmp.length;
            if ((tmp.length + generated) > len) {
                toCopy = len - generated;
            }
            System.arraycopy(tmp, 0, out, outOff, toCopy);
            generated += toCopy;
            outOff += toCopy;
        }
        return len;
    }
}