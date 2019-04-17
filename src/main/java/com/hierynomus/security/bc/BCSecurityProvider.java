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

import com.hierynomus.security.*;
import com.hierynomus.security.SecurityException;

/**
 * Generic BouncyCastle abstraction, in order to use Bouncy Castle directly when available.
 * This prevents the need to use strong cryptography extensions which are needed if BC is used
 * via JCE.
 */
public class BCSecurityProvider implements SecurityProvider {
    @Override
    public MessageDigest getDigest(String name) {
        return new BCMessageDigest(name);
    }

    @Override
    public Mac getMac(String name) {
        return new BCMac(name);
    }

    @Override
    public Cipher getCipher(String name) {
        return BCCipherFactory.create(name);
    }

    @Override
    public AEADBlockCipher getAEADBlockCipher(String name) throws SecurityException {
        return BCAEADCipherFactory.create(name);
    }

}
