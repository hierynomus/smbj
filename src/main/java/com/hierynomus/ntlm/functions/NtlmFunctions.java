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

import static com.hierynomus.security.Cipher.CryptMode.ENCRYPT;

import java.nio.charset.Charset;

import com.hierynomus.ntlm.NtlmException;
import com.hierynomus.protocol.commons.Charsets;
import com.hierynomus.security.Cipher;
import com.hierynomus.security.Mac;
import com.hierynomus.security.MessageDigest;
import com.hierynomus.security.SecurityException;
import com.hierynomus.security.SecurityProvider;

/**
 * NTLM Helper functions
 */
public class NtlmFunctions {

    public static final Charset UNICODE = Charsets.UTF_16LE;

    private NtlmFunctions() {
    }


    /**
     * [MS-NLMP].pdf 6 Appendix A: Cryptographic Operations Reference (UNICODE(string)).
     *
     * @param string The string to get the bytes of.
     * @return The 2-byte little endian byte order encoding of the Unicode UTF-16 representation of the string.
     */
    public static byte[] unicode(String string) {
        return string == null ? new byte[0] : string.getBytes(UNICODE);
    }

    public static String unicode(byte[] bytes) {
        return bytes != null ? new String(bytes, UNICODE) : "";
    }


    public static byte[] oem(String s) {
        return s != null ? s.getBytes(Charset.forName("Cp850")) : new byte[0];
    }

    public static String oem(byte[] bytes) {
        return bytes != null ? new String(bytes, Charset.forName("Cp850")) : "";
    }
    /**
     * [MS-NLMP].pdf 6 Appendix A: Cryptographic Operations Reference
     * (MD4(M)).
     *
     * @param m The string to calculcate the MD4 hash of.
     * @return The 2-byte little endian byte order encoding of the Unicode UTF-16
     *         representation of the string.
     */
    static byte[] md4(SecurityProvider securityProvider, byte[] m) {
        try {
            MessageDigest md4 = securityProvider.getDigest("MD4");
            md4.update(m);
            return md4.digest();
        } catch (SecurityException e) {
            throw new NtlmException(e);
        }
    }

    /**
     * [MS-NLMP].pdf 6 Appendix A: Cryptographic Operations Reference (HMAC_MD5(K, M)).
     *
     * @param key     The bytes of key K
     * @param message The bytes of message M
     * @return The 16-byte HMAC-keyed MD5 message digest of the byte string M using the key K
     */
    @SuppressWarnings("PMD.MethodNamingConventions")
    public static byte[] hmac_md5(SecurityProvider securityProvider, byte[] key, byte[]... message) {
        try {
            Mac hmacMD5 = securityProvider.getMac("HMACT64");
            hmacMD5.init(key);
            for (byte[] aMessage : message) {
                hmacMD5.update(aMessage);
            }
            return hmacMD5.doFinal();
        } catch (SecurityException e) {
            throw new NtlmException(e);
        }
    }

    public static byte[] md5(SecurityProvider securityProvider, byte[]... message) {
        try {
            MessageDigest md5 = securityProvider.getDigest("MD5");
            for (byte[] aMessage : message) {
                md5.update(aMessage);
            }
            return md5.digest();
        } catch (SecurityException e) {
            throw new NtlmException(e);
        }
    }

    /**
     * [MS-NLMP].pdf 6 Appendix A: Cryptographic Operations Reference
     * (RC4K(K, D)).
     *
     * @param k The key to initialize the RC4 cipher with.
     * @param d The data to encrypt.
     * @return The encrypted data.
     */
    public static byte[] rc4k(SecurityProvider securityProvider, byte[] k, byte[] d) throws NtlmException {
        byte[] out = new byte[d.length];
        try {
            Cipher cipher = securityProvider.getCipher("RC4");
            cipher.init(ENCRYPT, k);
            int bytes = cipher.update(d, 0, d.length, out, 0);
            cipher.doFinal(out, bytes);
        } catch (SecurityException e) {
            throw new NtlmException(e);
        }
        return out;
    }

    private static byte[] setupKey(byte[] key56) {
        byte[] key = new byte[8];
        key[0] = (byte) ((key56[0] >> 1) & 0xff);
        key[1] = (byte) ((((key56[0] & 0x01) << 6)
            | (((key56[1] & 0xff) >> 2) & 0xff)) & 0xff);
        key[2] = (byte) ((((key56[1] & 0x03) << 5)
            | (((key56[2] & 0xff) >> 3) & 0xff)) & 0xff);
        key[3] = (byte) ((((key56[2] & 0x07) << 4)
            | (((key56[3] & 0xff) >> 4) & 0xff)) & 0xff);
        key[4] = (byte) ((((key56[3] & 0x0f) << 3)
            | (((key56[4] & 0xff) >> 5) & 0xff)) & 0xff);
        key[5] = (byte) ((((key56[4] & 0x1f) << 2)
            | (((key56[5] & 0xff) >> 6) & 0xff)) & 0xff);
        key[6] = (byte) ((((key56[5] & 0x3f) << 1)
            | (((key56[6] & 0xff) >> 7) & 0xff)) & 0xff);
        key[7] = (byte) (key56[6] & 0x7f);

        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (key[i] << 1);
        }
        return key;
    }

    static Cipher getDESCipher(SecurityProvider securityProvider, byte[] key) {
        try {
            Cipher cipher = securityProvider.getCipher("DES/ECB/NoPadding");
            cipher.init(ENCRYPT, setupKey(key));
            return cipher;
        } catch (SecurityException e) {
            throw new NtlmException(e);
        }

    }
}
