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
package com.hierynomus.security;

/**
 * Abstraction layer over different Security Providers.
 * <p>
 * Using this you can easily choose to either use:
 * <p>
 * - Standard JCE
 * - BouncyCastle over JCE
 * - BouncyCastle direct
 * <p>
 * The advantage of using BouncyCastle directly is that you do not need to have the JCE
 * Unlimited Strength Cryptography policy files loaded in your JRE.
 */
public interface SecurityProvider {
    MessageDigest getDigest(String name) throws SecurityException;

    Mac getMac(String name) throws SecurityException;

    Cipher getCipher(String name) throws SecurityException;
}
