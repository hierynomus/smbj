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

import java.util.Random;

import org.bouncycastle.util.Arrays;

import com.hierynomus.ntlm.messages.NtlmChallenge;
import com.hierynomus.ntlm.messages.TargetInfo;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.security.SecurityProvider;

public class NtlmV2Functions {
    private Random random;
    private SecurityProvider securityProvider;

    public NtlmV2Functions(Random random, SecurityProvider securityProvider) {
        this.random = random;
        this.securityProvider = securityProvider;
    }

    /**
     * [MS-NLMP].pdf 3.3.2 NTLM v2 authentication.
     * <p/>
     *
     * {@code
     * Define ComputeResponse(NegFlg, ResponseKeyNT, ResponseKeyLM,
     * CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge, Time, ServerName) As
     * If (User is set to "" && Passwd is set to "")
     * -- Special case for anonymous authentication Set NtChallengeResponseLen to 0
     * Set NtChallengeResponseMaxLen to 0
     * Set NtChallengeResponseBufferOffset to 0 Set LmChallengeResponse to Z(1)
     * Else
     * Set temp to ConcatenationOf(Responserversion, HiResponserversion, Z(6), Time,
     * ClientChallenge, Z(4), ServerName, Z(4))
     * Set NTProofStr to HMAC_MD5(ResponseKeyNT,
     * ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge,temp))
     * Set NtChallengeResponse to ConcatenationOf(NTProofStr, temp)
     * Set LmChallengeResponse to ConcatenationOf(HMAC_MD5(ResponseKeyLM,
     * ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge)),
     * ClientChallenge )
     * EndIf
     * Set SessionBaseKey to HMAC_MD5(ResponseKeyNT, NTProofStr)
     * EndDefine
     * }
     */
    public ComputedNtlmV2Response computeResponse(String username, String domain, char[] password, NtlmChallenge serverNtlmChallenge, long time, TargetInfo clientTargetInfo) {
        // Create the client nonce
        byte[] clientChallenge = new byte[8];
        random.nextBytes(clientChallenge);

        byte[] responseKeyNT = NTOWFv2(String.valueOf(password), username, domain);
        byte[] responseKeyLM = LMOWFv2(String.valueOf(password), username, domain);

        byte[] lmResponse = getLmV2Response(responseKeyLM, serverNtlmChallenge.getServerChallenge(),
                    clientChallenge);

        byte[] ntResponse = getNtV2Response(responseKeyNT, serverNtlmChallenge.getServerChallenge(),
                clientChallenge, time, clientTargetInfo);

        byte[] ntProofStr = Arrays.copyOfRange(ntResponse, 0, 16);
        byte[] sessionBaseKey = getSessionBaseKey(responseKeyNT, ntProofStr);

        return new ComputedNtlmV2Response(ntResponse, lmResponse, sessionBaseKey);
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
        byte[] keyBytes = NtlmFunctions.md4(securityProvider, NtlmFunctions.unicode(password));
        byte[] usernameBytes = NtlmFunctions.unicode(username.toUpperCase());
        byte[] userDomainBytes = NtlmFunctions.unicode(userDomain);
        return NtlmFunctions.hmac_md5(securityProvider, keyBytes, usernameBytes, userDomainBytes);
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
     * [MS-NLMP].pdf 3.3.2 NTLM v2 authentication.
     * <p/>
     * <code>
     * Set LmChallengeResponse to ConcatenationOf(HMAC_MD5(ResponseKeyLM,
     *     ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge)),
     *     ClientChallenge)
     * </code>
     */
    public byte[] getLmV2Response(byte[] responseKeyLM, byte[] serverChallenge, byte[] clientChallenge) {
        Buffer.PlainBuffer respBuf = new Buffer.PlainBuffer(Endian.LE);
        byte[] hmac = NtlmFunctions.hmac_md5(securityProvider, responseKeyLM, serverChallenge, clientChallenge);
        respBuf.putRawBytes(hmac);
        respBuf.putRawBytes(clientChallenge);
        return respBuf.getCompactData();
    }


    /**
     * 3.3.2 NTLM v2 Authentication
     * <p/>
     *
     * <code>
     * Set temp to ntResponseTemp(ClientChallenge, TargetInfo) // See below
     * Set NTProofStr to HMAC_MD5(ResponseKeyNT,
     * ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge,temp))
     * Set NtChallengeResponse to ConcatenationOf(NTProofStr, temp)
     * </code>

     */
    public byte[] getNtV2Response(byte[] responseKeyNT, byte[] serverChallenge, byte[] clientChallenge, long time, TargetInfo targetInfo) {
        byte[] temp = ntResponseTemp(clientChallenge, time, targetInfo);
        byte[] ntProofStr = ntProofStr(responseKeyNT, serverChallenge, temp);

        byte[] ntChallengeResponse = new byte[ntProofStr.length + temp.length];
        System.arraycopy(ntProofStr, 0, ntChallengeResponse, 0, ntProofStr.length);
        System.arraycopy(temp, 0, ntChallengeResponse, ntProofStr.length,
                temp.length);

        return ntChallengeResponse;
    }

    /**
     * [MS-NLMP].pdf 3.3.2 NTLM v2 authentication.
     * <p/>
     *
     * <code>
     * Set SessionBaseKey to HMAC_MD5(ResponseKeyNT, NTProofStr)
     * </code>
     */
    public byte[] getSessionBaseKey(byte[] responseKeyNT, byte[] ntProofStr) {
        return NtlmFunctions.hmac_md5(securityProvider, responseKeyNT, ntProofStr);
    }

    /**
     * [MS-NLMP].pdf 2.2.2.7 NTLM v2: (temp)
     * <p/>
     *
     * <code>
     * Set temp to ConcatenationOf(Responserversion, HiResponserversion, Z(6), Time,
     * ClientChallenge, Z(4), ServerName, Z(4))
     * </code>
     */
    byte[] ntResponseTemp(byte[] clientChallenge, long time, TargetInfo targetInfo) {
        Buffer.PlainBuffer ccBuf = new Buffer.PlainBuffer(Endian.LE);
        ccBuf.putByte((byte) 0x01); // RespType (1)
        ccBuf.putByte((byte) 0x01); // HiRespType (1)
        ccBuf.putUInt16(0); // Reserved1 (2)
        ccBuf.putUInt32(0); // Reserved2 (4)
        ccBuf.putLong(time); // Timestamp (8)
        ccBuf.putRawBytes(clientChallenge); // ChallengeFromClient (8)
        ccBuf.putUInt32(0); // Reserved3 (4)
        if (targetInfo != null) {
            targetInfo.writeTo(ccBuf);
        }
        ccBuf.putUInt32(0); // Reserved4 (4)

        return ccBuf.getCompactData();
    }

    /**
     * [MS-NLMP].pdf 3.3.2 NTLM v2 authentication (NTProofStr).
     * <p/>
     *
     * <code>
     * Define NTProofStr(ResponseKeyNT, ServerChallenge, temp) as HMAC_MD5(ResponseKeyNT,
     * ConcatenationOf(ServerChallenge, temp))
     * EndDefine
     * </code>
     */
    byte[] ntProofStr(byte[] responseKeyNT, byte[] serverChallenge, byte[] temp) {
        return NtlmFunctions.hmac_md5(securityProvider, responseKeyNT, serverChallenge, temp);
    }

    /**
     * [MS-NLMP].pdf 3.4.5.1 KXKEY
     *
     * If NTLM v2 is used, KeyExchangeKey MUST be set to the given 128-bit
     * SessionBaseKey value.
     */
    public byte[] kxKey(byte[] sessionBaseKey, byte[] lmResponse, byte[] serverChallenge) {
        return sessionBaseKey;
    }
}
