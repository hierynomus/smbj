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

import javax.crypto.spec.GCMParameterSpec;

public interface AEADBlockCipher {

    void init(Cipher.CryptMode cryptMode, byte[] bytes, GCMParameterSpec gcmParameterSpec) throws SecurityException;

    void updateAAD(byte[] aad, int aadOffset, int aadLength) throws SecurityException;

    byte[] update(byte[] in, int inOffset, int inLength) throws SecurityException;

    byte[] doFinal(byte[] in, int inOffset, int inLength) throws SecurityException;

    void reset();

}
