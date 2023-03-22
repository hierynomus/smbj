package com.hierynomus.ntlm.functions;

import java.util.Random;

import com.hierynomus.msdtyp.FileTime;
import com.hierynomus.msdtyp.MsDataTypes;
import com.hierynomus.ntlm.messages.AvId;
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
     * 3.3.2 NTLM v2 Authentication
     * <p>
     * Set NTProofStr to HMAC_MD5(ResponseKeyNT,
     * ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge,temp))
     * Set NtChallengeResponse to ConcatenationOf(NTProofStr, temp)
     *
     * @param responseKeyNT
     * @param serverChallenge
     * @param ntlmv2ClientChallenge (temp from above)
     * @return
     */
    public byte[] getNTLMv2Response(byte[] responseKeyNT, byte[] serverChallenge, byte[] ntlmv2ClientChallenge) {
        byte[] ntProofStr = ntProofStr(responseKeyNT, serverChallenge, ntlmv2ClientChallenge);

        byte[] ntChallengeResponse = new byte[ntProofStr.length + ntlmv2ClientChallenge.length];
        System.arraycopy(ntProofStr, 0, ntChallengeResponse, 0, ntProofStr.length);
        System.arraycopy(ntlmv2ClientChallenge, 0, ntChallengeResponse, ntProofStr.length,
                ntlmv2ClientChallenge.length);

        return ntChallengeResponse;
    }

    /**
     * [MS-NLMP].pdf 2.2.2.7 NTLM v2: NTLMv2_CLIENT_CHALLENGE
     * <p>
     * 3.3.2 NTLM v2 Authentication
     * Set temp to ConcatenationOf(Responserversion, HiResponserversion, Z(6), Time,
     * ClientChallenge, Z(4), ServerName, Z(4))
     *
     * @param targetInformation
     * @return
     */
    public byte[] clientChallenge(TargetInfo targetInfo) {
        byte[] clientChallenge = new byte[8];
        random.nextBytes(clientChallenge);

        long time = MsDataTypes.nowAsFileTime();
        if (targetInfo.hasAvPair(AvId.MsvAvTimestamp)) {
            time = ((FileTime) targetInfo.getAvPairObject(AvId.MsvAvTimestamp)).getWindowsTimeStamp();
        }
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
        // ccBuf.putUInt32(0); // Last AV Pair indicator

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
    public byte[] ntProofStr(byte[] responseKeyNT, byte[] serverChallenge, byte[] temp) {
        return NtlmFunctions.hmac_md5(securityProvider, responseKeyNT, serverChallenge, temp);
    }
}
