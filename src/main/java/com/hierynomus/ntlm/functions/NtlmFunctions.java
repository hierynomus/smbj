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

import com.hierynomus.msdtyp.MsDataTypes;
import com.hierynomus.ntlm.NtlmException;
import com.hierynomus.ntlm.messages.TargetInfo;
import com.hierynomus.protocol.commons.Charsets;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.security.Cipher;
import com.hierynomus.security.SecurityException;
import com.hierynomus.security.SecurityProvider;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Random;

import static com.hierynomus.security.Cipher.CryptMode.ENCRYPT;

/**
 * NTLM Helper functions
 */
public class NtlmFunctions {

    static final byte[] LMOWFv1_SECRET = new byte[]{0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25}; // KGS!@#$%

    public static final Charset UNICODE = Charsets.UTF_16LE;

    private final Random random;
    private final SecurityProvider securityProvider;

    public NtlmFunctions(Random random, SecurityProvider securityProvider) {
        this.random = random;
        this.securityProvider = securityProvider;
    }

    /**
     * [MS-NLMP].pdf 3.3.2 NTLM v2 authentication (NTOWF v2).
     * <p/>
     * <code>
     * Define NTOWFv2(Passwd, User, UserDom) as HMAC_MD5( MD4(UNICODE(Passwd)), UNICODE(ConcatenationOf( Uppercase(User), UserDom ) ) )
     * EndDefine
     * </code>
     */
    @SuppressWarnings("PMD.MethodNamingConventions")
    public byte[] NTOWFv2(String password, String username, String userDomain) {
        byte[] keyBytes = NTOWFv1(password, username, userDomain);
        byte[] usernameBytes = unicode(username.toUpperCase());
        byte[] userDomainBytes = unicode(userDomain);
        return hmac_md5(keyBytes, usernameBytes, userDomainBytes);
    }

    /**
     * [MS-NLMP].pdf 3.3.2 NTLM v2 authentication (NTOWF v2).
     * <p/>
     * <code>
     * Define LMOWFv2(Passwd, User, UserDom) as NTOWFv2(Passwd, User, UserDom)
     * EndDefine
     * </code>
     */
    @SuppressWarnings("PMD.MethodNamingConventions")
    public byte[] LMOWFv2(String password, String username, String userDomain) {
        return NTOWFv2(password, username, userDomain);
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
        byte[] bytes = unicode(password);
        try {
            com.hierynomus.security.MessageDigest md4 = securityProvider.getDigest("MD4");
            md4.update(bytes);
            return md4.digest();
        } catch (SecurityException e) {
            throw new NtlmException(e);
        }
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

    /**
     * [MS-NLMP].pdf 6 Appendix A: Cryptographic Operations Reference (HMAC_MD5(K, M)).
     *
     * @param key     The bytes of key K
     * @param message The bytes of message M
     * @return The 16-byte HMAC-keyed MD5 message digest of the byte string M using the key K
     */
    @SuppressWarnings("PMD.MethodNamingConventions")
    public byte[] hmac_md5(byte[] key, byte[]... message) {
        try {
            com.hierynomus.security.Mac hmacMD5 = securityProvider.getMac("HmacMD5");
            hmacMD5.init(key);
            for (byte[] aMessage : message) {
                hmacMD5.update(aMessage);
            }
            return hmacMD5.doFinal();
        } catch (SecurityException e) {
            throw new NtlmException(e);
        }
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
     *
     * @param password
     * @param username
     * @param userDomain
     * @return
     */
    @SuppressWarnings("PMD.MethodNamingConventions")
    public byte[] LMOWFv1(String password, String username, String userDomain) {
        try {
            byte[] bytes = password.toUpperCase().getBytes("US-ASCII");
            if (bytes.length != 14) {
                bytes = Arrays.copyOf(bytes, 14);
            }
            Cipher leftCipher = getDESCipher(Arrays.copyOfRange(bytes, 0, 7));
            Cipher rightCipher = getDESCipher(Arrays.copyOfRange(bytes, 7, 14));

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

    /**
     * [MS-NLMP].pdf 2.2.2.7 NTLM v2: NTLMv2_CLIENT_CHALLENGE
     * <p>
     * 3.3.2 NTLM v2 Authentication
     * Set temp to ConcatenationOf(Responserversion, HiResponserversion, Z(6), Time, ClientChallenge, Z(4), ServerName, Z(4))
     *
     * @param targetInformation
     * @return
     */
    public byte[] getNTLMv2ClientChallenge(TargetInfo targetInformation) {

        byte[] challengeFromClient = new byte[8];
        random.nextBytes(challengeFromClient);

        long nowAsFileTime = MsDataTypes.nowAsFileTime();
        Buffer.PlainBuffer ccBuf = new Buffer.PlainBuffer(Endian.LE);
        ccBuf.putByte((byte) 0x01); // RespType (1)
        ccBuf.putByte((byte) 0x01); // HiRespType (1)
        ccBuf.putUInt16(0); // Reserved1 (2)
        ccBuf.putUInt32(0); // Reserved2 (4)
        ccBuf.putLong(nowAsFileTime); // Timestamp (8)
        ccBuf.putRawBytes(challengeFromClient); // ChallengeFromClient (8)
        ccBuf.putUInt32(0); // Reserved3 (4)
        targetInformation.writeTo(ccBuf); // AvPairs (variable)
        ccBuf.putUInt32(0); // Last AV Pair indicator

        return ccBuf.getCompactData();
    }

    /**
     * 3.3.2 NTLM v2 Authentication
     * <p>
     * Set NTProofStr to HMAC_MD5(ResponseKeyNT, ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge,temp))
     * Set NtChallengeResponse to ConcatenationOf(NTProofStr, temp)
     *
     * @param responseKeyNT
     * @param serverChallenge
     * @param ntlmv2ClientChallenge (temp from above)
     * @return
     */
    public byte[] getNTLMv2Response(byte[] responseKeyNT, byte[] serverChallenge, byte[] ntlmv2ClientChallenge) {

        byte[] ntProofStr = hmac_md5(responseKeyNT, serverChallenge, ntlmv2ClientChallenge);

        byte[] ntChallengeResponse = new byte[ntProofStr.length + ntlmv2ClientChallenge.length];
        System.arraycopy(ntProofStr, 0, ntChallengeResponse, 0, ntProofStr.length);
        System.arraycopy(ntlmv2ClientChallenge, 0, ntChallengeResponse, ntProofStr.length, ntlmv2ClientChallenge.length);

        return ntChallengeResponse;
    }


    public byte[] encryptRc4(byte[] key, byte[] val) throws NtlmException {
        Cipher c = getRC4Cipher(key);
        byte[] out = new byte[val.length];
        try {
            int bytes = c.update(val, 0, val.length, out, 0);
            c.doFinal(out, bytes);
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

    private Cipher getDESCipher(byte[] key) {
        try {
            Cipher cipher = securityProvider.getCipher("DES/ECB/NoPadding");
            cipher.init(ENCRYPT, setupKey(key));
            return cipher;
        } catch (SecurityException e) {
            throw new NtlmException(e);
        }

    }

    private Cipher getRC4Cipher(byte[] key) {
        try {
            Cipher cipher = securityProvider.getCipher("RC4");
            cipher.init(ENCRYPT, key);
            return cipher;
        } catch (SecurityException e) {
            throw new NtlmException(e);
        }

    }

}
