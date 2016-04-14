/*
 * Copyright (C)2016 - Jeroen van Erp <jeroen@hierynomus.com>
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

import com.hierynomus.ntlm.NtlmException;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import org.bouncycastle.jcajce.provider.digest.MD4;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * NTLM Helper functions
 */
public class NtlmFunctions {

    static final byte[] LMOWFv1_SECRET = new byte[]{0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25}; // KGS!@#$%

    public static final SecureRandom RANDOM = new SecureRandom();

    /**
     * [MS-NLMP].pdf 3.3.2 NTLM v2 authentication (NTOWF v2).
     * <p/>
     * <code>
     * Define NTOWFv2(Passwd, User, UserDom) as HMAC_MD5( MD4(UNICODE(Passwd)), UNICODE(ConcatenationOf( Uppercase(User), UserDom ) ) )
     * EndDefine
     * </code>
     */
    public static byte[] NTOWFv2(String password, String username, String userDomain) {
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
    public static byte[] LMOWFv2(String password, String username, String userDomain) {
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
    public static byte[] NTOWFv1(String password, String username, String userDomain) {
        byte[] bytes = unicode(password);
        MD4.Digest digest = new MD4.Digest();
        digest.update(bytes);
        return digest.digest();
    }

    /**
     * [MS-NLMP].pdf 6 Appendix A: Cryptographic Operations Reference (UNICODE(string)).
     *
     * @param string The string to get the bytes of.
     * @return The 2-byte little endian byte order encoding of the Unicode UTF-16 representation of the string.
     */
    public static byte[] unicode(String string) {
        try {
            return string.getBytes("UTF-16LE");
        } catch (UnsupportedEncodingException uee) {
            throw new NtlmException(uee);
        }
    }

    /**
     * [MS-NLMP].pdf 6 Appendix A: Cryptographic Operations Reference (HMAC_MD5(K, M)).
     *
     * @param key     The bytes of key K
     * @param message The bytes of message M
     * @return The 16-byte HMAC-keyed MD5 message digest of the byte string M using the key K
     */
    public static byte[] hmac_md5(byte[] key, byte[]... message) {
        try {
            javax.crypto.Mac hmacMD5 = javax.crypto.Mac.getInstance("HmacMD5");
            hmacMD5.init(new SecretKeySpec(key, "HmacMD5"));
            for (int i = 0; i < message.length; i++) {
                hmacMD5.update(message[i]);
            }
            return hmacMD5.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
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
    public static byte[] LMOWFv1(String password, String username, String userDomain) {
        try {
            byte[] bytes = password.toUpperCase().getBytes("US-ASCII");
            if (bytes.length != 14) {
                bytes = Arrays.copyOf(bytes, 14);
            }
            Cipher leftCipher = getDESCipher(Arrays.copyOfRange(bytes, 0, 7));
            Cipher rightCipher = getDESCipher(Arrays.copyOfRange(bytes, 7, 14));

            byte[] firstBytes = leftCipher.doFinal(LMOWFv1_SECRET);
            byte[] lastBytes = rightCipher.doFinal(LMOWFv1_SECRET);

            byte[] lmHash = new byte[16];
            System.arraycopy(firstBytes, 0, lmHash, 0, firstBytes.length);
            System.arraycopy(lastBytes, 0, lmHash, firstBytes.length, lastBytes.length);
            return lmHash;
        } catch (UnsupportedEncodingException | BadPaddingException | IllegalBlockSizeException e) {
            throw new NtlmException(e);
        }
    }

    /**
     * [MS-NLMP].pdf 2.2.2.7 NTLM v2: NTLMv2_CLIENT_CHALLENGE
     *
     * 3.3.2 NTLM v2 Authentication
     * Set temp to ConcatenationOf(Responserversion, HiResponserversion, Z(6), Time, ClientChallenge, Z(4), ServerName, Z(4))
     *
     * @param challengeFromClient
     * @param targetInformation
     * @return
     */
    public static byte[] getNTLMv2ClientChallenge(
                                                  byte[] challengeFromClient,
                                                  byte[] targetInformation
                                                  ) {
        if (challengeFromClient == null) {
            return null;
        }
        long nanos1601 = getTimeStampNanos1601();
        byte[] l_targetInfo = (targetInformation == null) ? new byte[0] : targetInformation;
        Buffer.PlainBuffer ccBuf = new Buffer.PlainBuffer(Endian.LE);
        ccBuf.putByte((byte)0x01); // RespType (1)
        ccBuf.putByte((byte)0x01); // HiRespType (1)
        ccBuf.putUInt16(0); // Reserved1 (2)
        ccBuf.putUInt32(0); // Reserved2 (4)
        ccBuf.putLong(nanos1601); // Timestamp (8)
        ccBuf.putRawBytes(challengeFromClient); // ChallengeFromClient (8)
        ccBuf.putUInt32(0); // Reserver3 (4)
        ccBuf.putRawBytes(l_targetInfo);
        ccBuf.putUInt32(0); // Last AV Pair indicator

        return ccBuf.getCompactData();
    }

    /**
     *
     * 3.3.2 NTLM v2 Authentication
     *
     * Set NTProofStr to HMAC_MD5(ResponseKeyNT, ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge,temp))
     * Set NtChallengeResponse to ConcatenationOf(NTProofStr, temp)
     *
     * @param responseKeyNT
     * @param serverChallenge
     * @param ntlmv2ClientChallenge (temp from above)
     * @return
     */
    public static byte[] getNTLMv2Response(byte[] responseKeyNT, byte[] serverChallenge, byte[] ntlmv2ClientChallenge) {

        byte[] ntProofStr = hmac_md5(responseKeyNT, serverChallenge, ntlmv2ClientChallenge);

        byte[] ntChallengeResponse = ByteBuffer.allocate(ntProofStr.length + ntlmv2ClientChallenge.length)
                .put(ntProofStr).put(ntlmv2ClientChallenge).array();

        return ntChallengeResponse;
    }

    public static byte[] encryptRc4(byte[] key, byte[] val) throws BadPaddingException, IllegalBlockSizeException {
        Cipher c = getRC4Cipher(key);
        byte[] enc = c.doFinal(val);
        return enc;
    }

    /**
     * A 64-bit unsigned integer that contains the current system time, represented
     * as the number of 100 nanosecond ticks elapsed since midnight of January 1, 1601 (UTC)
     */
    private static long getTimeStampNanos1601() {
        final long MILLISECONDS_BETWEEN_1970_AND_1601 = 11644473600000L;

        return (System.currentTimeMillis() + MILLISECONDS_BETWEEN_1970_AND_1601) * 10000L;
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

    private static Cipher getDESCipher(byte[] key) {
        try {
            Cipher bc = Cipher.getInstance("DES/ECB/NoPadding", "BC");
            SecretKeySpec des = new SecretKeySpec(setupKey(key), "DES");
            bc.init(Cipher.ENCRYPT_MODE, des);
            return bc;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException | InvalidKeyException e) {
            throw new NtlmException(e);
        }

    }

    private static Cipher getRC4Cipher(byte[] key) {
        try {
            Cipher bc = Cipher.getInstance("RC4", "BC");
            SecretKeySpec rc4 = new SecretKeySpec(setupKey(key), "RC4");
            bc.init(Cipher.ENCRYPT_MODE, rc4);
            return bc;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException | InvalidKeyException e) {
            throw new NtlmException(e);
        }

    }

}
