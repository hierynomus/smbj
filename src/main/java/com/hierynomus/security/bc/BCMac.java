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
import com.hierynomus.security.Mac;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.HashMap;
import java.util.Map;

public class BCMac implements Mac {
    private static Map<String, Factory<org.bouncycastle.crypto.Mac>> lookup = new HashMap<>();

    static {
        lookup.put("HMACSHA256", new Factory<org.bouncycastle.crypto.Mac>() {
            @Override
            public org.bouncycastle.crypto.Mac create() {
                return new HMac(new SHA256Digest());
            }
        });
        lookup.put("HMACMD5", new Factory<org.bouncycastle.crypto.Mac>() {
            @Override
            public org.bouncycastle.crypto.Mac create() {
                return new HMac(new MD5Digest());
            }
        });
    }

    private final org.bouncycastle.crypto.Mac mac;

    BCMac(String name) {
        this.mac = getMacFactory(name).create();
    }

    private Factory<org.bouncycastle.crypto.Mac> getMacFactory(String name) {
        Factory<org.bouncycastle.crypto.Mac> macFactory = lookup.get(name.toUpperCase());
        if (macFactory == null) {
            throw new IllegalArgumentException("No Mac defined for " + name);
        }
        return macFactory;
    }

    @Override
    public void init(byte[] key) {
        mac.init(new KeyParameter(key));
    }

    @Override
    public void update(byte b) {
        mac.update(b);
    }

    @Override
    public void update(byte[] array) {
        mac.update(array, 0, array.length);
    }

    @Override
    public void update(byte[] array, int offset, int length) {
        mac.update(array, offset, length);
    }

    @Override
    public byte[] doFinal() {
        byte[] output = new byte[mac.getMacSize()];
        mac.doFinal(output, 0);
        return output;
    }

    @Override
    public void reset() {
        mac.reset();
    }
}
