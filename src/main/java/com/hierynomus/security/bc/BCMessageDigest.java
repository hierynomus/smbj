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
import com.hierynomus.security.MessageDigest;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

import java.util.HashMap;
import java.util.Map;

public class BCMessageDigest implements MessageDigest {
    private static Map<String, Factory<Digest>> lookup = new HashMap<>();

    static {
        lookup.put("SHA256", new Factory<Digest>() {
            @Override
            public Digest create() {
                return new SHA256Digest();
            }
        });
        lookup.put("MD4", new Factory<Digest>() {
            @Override
            public Digest create() {
                return new MD4Digest();
            }
        });
    }

    private final Digest digest;

    BCMessageDigest(String name) {
        this.digest = getDigest(name);
    }

    private Digest getDigest(String name) {
        Factory<Digest> digestFactory = lookup.get(name);
        if (digestFactory == null) {
            throw new IllegalArgumentException("No MessageDigest " + name + " defined in BouncyCastle");
        }
        return digestFactory.create();
    }

    @Override
    public void update(byte[] bytes) {
        digest.update(bytes, 0, bytes.length);
    }

    @Override
    public byte[] digest() {
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        return output;
    }

    @Override
    public void reset() {
        digest.reset();
    }
}
