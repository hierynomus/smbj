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
package com.hierynomus.ntlm.functions;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Random;

import com.hierynomus.ntlm.NtlmException;
import com.hierynomus.security.Cipher;
import com.hierynomus.security.SecurityException;
import com.hierynomus.security.SecurityProvider;

class NtlmV1Functions {
    static final byte[] LMOWFv1_SECRET = new byte[] { 0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 }; // KGS!@#$%

    private Random random;
    private SecurityProvider securityProvider;

    public NtlmV1Functions(Random random, SecurityProvider securityProvider) {
        this.random = random;
        this.securityProvider = securityProvider;
    }

    /**
     * [MS-NLMP].pdf 3.3.1 NTLM v1 authentication (NTOWF v1).
     * <p/>
     * <code>
     * Define NTOWFv1(Passwd, User, UserDom) as MD4(UNICODE(Passwd))
     * EndDefine
     * </code>
     */
    @SuppressWarnings("PMD.MethodNamingConventions")
    public byte[] NTOWFv1(String password, String username, String userDomain) {
        return NtlmFunctions.md4(securityProvider, NtlmFunctions.unicode(password));
    }

    /**
     * [MS-NLMP].pdf 3.3.1 NTLM v1 authentication (LMOWF v1).
     * <p/>
     * <code>
     * Define LMOWFv1(Passwd, User, UserDom) as
     * ConcatenationOf(
     * DES(UpperCase(Passwd)[0..6], "KGS!@#$%"),
     * DES(UpperCase(Passwd)[7..13], "KGS!@#$%"))
     * EndDefine
     * </code>
     */
    @SuppressWarnings("PMD.MethodNamingConventions")
    public byte[] LMOWFv1(String password, String username, String userDomain) {
        try {
            byte[] bytes = password.toUpperCase().getBytes("US-ASCII");
            if (bytes.length != 14) {
                bytes = Arrays.copyOf(bytes, 14);
            }
            Cipher leftCipher = NtlmFunctions.getDESCipher(securityProvider, Arrays.copyOfRange(bytes, 0, 7));
            Cipher rightCipher = NtlmFunctions.getDESCipher(securityProvider, Arrays.copyOfRange(bytes, 7, 14));

            byte[] lmHash = new byte[16];
            int outOff = leftCipher.update(LMOWFv1_SECRET, 0, LMOWFv1_SECRET.length, lmHash, 0);
            outOff += leftCipher.doFinal(lmHash, outOff);
            outOff += rightCipher.update(LMOWFv1_SECRET, 0, LMOWFv1_SECRET.length, lmHash, outOff);
            outOff += rightCipher.doFinal(lmHash, outOff);
            if (outOff != 16) {
                throw new NtlmException("Incorrect lmHash calculated");
            }
            return lmHash;
        } catch (UnsupportedEncodingException | SecurityException e) {
            throw new NtlmException(e);
        }
    }

}
