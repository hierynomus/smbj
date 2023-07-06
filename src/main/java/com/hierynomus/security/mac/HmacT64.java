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
package com.hierynomus.security.mac;

import com.hierynomus.security.Mac;
import com.hierynomus.security.MessageDigest;
import com.hierynomus.security.SecurityException;

/**
 * This is an implementation of the HMACT64 keyed hashing algorithm.
 * HMACT64 is defined by Luke Leighton as a modified HMAC-MD5 (RFC 2104)
 * in which the key is truncated at 64 bytes (rather than being hashed
 * via MD5).
 */
public class HmacT64 implements Mac {

    private static final int BLOCK_LENGTH = 64;

    private static final byte IPAD = (byte) 0x36;

    private static final byte OPAD = (byte) 0x5c;

    private MessageDigest md5;

    private byte[] ipad = new byte[BLOCK_LENGTH];

    private byte[] opad = new byte[BLOCK_LENGTH];

    /**
     * Creates an HMACT64 instance which uses the given secret key material.
     */
    public HmacT64(MessageDigest md5) {
        super();
        this.md5 = md5;
    }

    @Override
    public void init(byte[] key) throws SecurityException {
        if (key == null) {
            throw new SecurityException("Missing key data");
        }

        int length = Math.min(key.length, BLOCK_LENGTH);
        for (int i = 0; i < length; i++) {
            ipad[i] = (byte) (key[i] ^ IPAD);
            opad[i] = (byte) (key[i] ^ OPAD);
        }

        for (int i = length; i < BLOCK_LENGTH; i++) {
            ipad[i] = IPAD;
            opad[i] = OPAD;
        }

        reset();

    }

    @Override
    public byte[] doFinal() {
        try {
            // finish the inner digest
            byte[] tmp = md5.digest();

            // compute digest for 2nd pass; start with outer pad
            md5.update(opad);
            // add result of 1st hash
            md5.update(tmp);

            tmp = md5.digest();

            return tmp;
        } finally {
            // reset the digest for further use
            reset();
        }
    }

    @Override
    public void update(byte b) {
        md5.update(b);
    }

    @Override
    public void update(byte[] array) {
        md5.update(array);
    }

    @Override
    public void update(byte[] array, int offset, int length) {
        md5.update(array, offset, length);
    }

    @Override
    public void reset() {
        md5.reset();
        md5.update(ipad, 0, ipad.length);
    }
}

