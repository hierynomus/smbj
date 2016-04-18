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
package com.hierynomus.ntlm.messages;

import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;

import java.nio.charset.Charset;

import static com.hierynomus.ntlm.functions.NtlmFunctions.unicode;

/**
 * [MS-NLMP].pdf 2.2.1.3 AUTHENTICATE_MESSAGE
 */
public class NtlmAuthenticate extends NtlmPacket {
    private static byte[] EMPTY = new byte[0];

    byte[] lmResponse;
    byte[] ntResponse;
    byte[] userName;
    byte[] domainName;
    byte[] workStation;
    byte[] encryptedRandomSessionKey;
    long negotiateFlags = NtlmNegotiate.DEFAULT_FLAGS;

    public NtlmAuthenticate(
            byte[] lmResponse, byte[] ntResponse,
            String userName, String domainName, String workStation,
            byte[] encryptedRandomSessionKey, long negotiateFlags
    ) {
        super();
        this.lmResponse = ensureNotNull(lmResponse);
        this.ntResponse = ensureNotNull(ntResponse);
        this.userName = ensureNotNull(userName);
        this.domainName = ensureNotNull(domainName);
        this.workStation = ensureNotNull(workStation);
        this.encryptedRandomSessionKey = ensureNotNull(encryptedRandomSessionKey);
        this.negotiateFlags = negotiateFlags;
    }

    @Override
    public void write(Buffer.PlainBuffer buffer) {
        buffer.putString("NTLMSSP\0", Charset.forName("UTF-8")); // Signature (8 bytes)
        buffer.putUInt32(0x03); // MessageType (4 bytes)

        int offset = 80; // for the offset

        buffer.putUInt16(lmResponse.length); // LmChallengeResponseLen (2 bytes)
        buffer.putUInt16(lmResponse.length); // LmChallengeResponseMaxLen (2 bytes)
        buffer.putUInt32(offset); // LmChallengeResponseBufferOffset (4 bytes)
        offset += lmResponse.length;

        buffer.putUInt16(ntResponse.length); // NtChallengeResponseLen (2 bytes)
        buffer.putUInt16(ntResponse.length); // NtChallengeResponseMaxLen (2 bytes)
        buffer.putUInt32(offset); // NtChallengeResponseBufferOffset (4 bytes)
        offset += ntResponse.length;

        buffer.putUInt16(domainName.length); // DomainNameLen (2 bytes)
        buffer.putUInt16(domainName.length); // DomainNameMaxLen (2 bytes)
        buffer.putUInt32(offset); // DomainNameBufferOffset (4 bytes)
        offset += domainName.length;

        buffer.putUInt16(userName.length); // UserNameLen (2 bytes)
        buffer.putUInt16(userName.length); // UserNameMaxLen (2 bytes)
        buffer.putUInt32(offset); // UserNameBufferOffset (4 bytes)
        offset += userName.length;

        buffer.putUInt16(workStation.length); // WorkstationLen (2 bytes)
        buffer.putUInt16(workStation.length); // WorkstationMaxLen (2 bytes)
        buffer.putUInt32(offset); // WorkstationBufferOffset (4 bytes)
        offset += workStation.length;

        byte[] _sessionKey = (encryptedRandomSessionKey == null) ? new byte[0] : encryptedRandomSessionKey;
        buffer.putUInt16(_sessionKey.length); // EncryptedRandomSessionKeyLen (2 bytes)
        buffer.putUInt16(_sessionKey.length); // EncryptedRandomSessionKeyMaxLen (2 bytes)
        buffer.putUInt32(offset); // EncryptedRandomSessionKeyBufferOffset (4 bytes)
        offset += _sessionKey.length;

        buffer.putUInt32(negotiateFlags); // NegotiateFlags (4 bytes)

        if (EnumWithValue.EnumUtils.isSet(negotiateFlags, NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_VERSION)) {
            buffer.putRawBytes(getVersion()); // Version (8 bytes)
        }

        // MIC
        // TODO Set MIC to HMAC_MD5(ExportedSessionKey, ConcatenationOf( CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE))
        byte[] MIC = new byte[16];
        buffer.putRawBytes(MIC); // MIC (16 bytes)

        // Payload
        buffer.putRawBytes(lmResponse);
        buffer.putRawBytes(ntResponse);
        buffer.putRawBytes(domainName);
        buffer.putRawBytes(userName);
        buffer.putRawBytes(workStation);
        buffer.putRawBytes(_sessionKey);
    }

    /**
     * MS-NLMP 2.2.2.10 VERSION
     * @return
     */
    public byte[] getVersion() {
        Buffer.PlainBuffer plainBuffer = new Buffer.PlainBuffer(Endian.LE);
        plainBuffer.putByte((byte)0x06); // Major Version 6
        plainBuffer.putByte((byte)0x01); // Minor Version 1
        plainBuffer.putUInt16(7600); // Product Build 7600
        byte[] reserved = {(byte)0x00, (byte)0x00, (byte)0x00};
        plainBuffer.putRawBytes(reserved); // Reserver 3 bytes
        plainBuffer.putByte((byte)0x0F); // NTLM Revision Current
        return plainBuffer.getCompactData();
    }

    private byte[] ensureNotNull(byte[] possiblyNull) {
        return possiblyNull != null ? possiblyNull : EMPTY;
    }

    private byte[] ensureNotNull(String possiblyNull) {
        return possiblyNull != null ? unicode(possiblyNull) : EMPTY;
    }
}

//
//
///**
// * [MS-NLMP].pdf 2.2.1.3 AUTHENTICATE_MESSAGE
// */
//public class NtlmAuthenticate extends NtlmPacket {
//    private static byte[] EMPTY = new byte[0];
//
//    private byte[] lmResponse;
//    private byte[] ntResponse;
//    private String userName;
//    private String domainName;
//    private String workstation;
//    private byte[] encryptedRandomSessionKey;
//    private final long negotiateFlags;
//
//    public NtlmAuthenticate(
//            byte[] lmResponse, byte[] ntResponse,
//            String userName, String domainName, String workstation,
//            byte[] encryptedRandomSessionKey, long negotiateFlags
//    ) {
//        super();
//        this.lmResponse = lmResponse;
//        this.ntResponse = ntResponse;
//        this.userName = userName;
//        this.domainName = domainName;
//        this.workstation = workstation;
//        this.encryptedRandomSessionKey = encryptedRandomSessionKey;
//        this.negotiateFlags = negotiateFlags;
//    }
//
//    public void write(NtlmBuffer buffer) {
//        buffer.putString("NTLMSSP\0", Charset.forName("UTF-8")); // Signature (8 bytes)
//        buffer.putUInt32(0x03); // MessageType (4 bytes)
//
//        int offset = 80; // for the offset
//
//        offset = buffer.putOffsettedByteArray(lmResponse, offset); // LmChallengeFields (8 bytes) + LmChallenge
//        offset = buffer.putOffsettedByteArray(ntResponse, offset); // NtChallengeResponseFields (8 bytes) + NtChallengeResponse
//        offset = buffer.putOffsettedString(domainName, offset); // DomainNameFields (8 bytes) + DomainName
//        offset = buffer.putOffsettedString(userName, offset); // UserNameFields (8 bytes) + UserName
//        offset = buffer.putOffsettedString(workstation, offset); // WorkstationFields (8 bytes) + Workstation
//        if (EnumWithValue.EnumUtils.isSet(negotiateFlags, NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_KEY_EXCH)) {
//            offset = buffer.putOffsettedByteArray(encryptedRandomSessionKey, offset);
//        } else {
//            offset = buffer.putOffsettedByteArray(NtlmBuffer.EMPTY, offset);
//        }
//
//        buffer.putUInt32(negotiateFlags); // Flags
//
//        if (EnumWithValue.EnumUtils.isSet(negotiateFlags, NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_VERSION)) {
//            buffer.putBuffer(getVersion());
//        }
//
//        // MIC
//        // TODO Set MIC to HMAC_MD5(ExportedSessionKey, ConcatenationOf( CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE))
//        byte[] MIC = new byte[16];
//        buffer.putRawBytes(MIC);
//    }
//
//    /**
//     * MS-NLMP 2.2.2.10 VERSION
//     * @return
//     */
//    public Buffer.PlainBuffer getVersion() {
//        Buffer.PlainBuffer plainBuffer = new Buffer.PlainBuffer(Endian.LE);
//        plainBuffer.putByte((byte)0x06); // Major Version 6
//        plainBuffer.putByte((byte)0x01); // Minor Version 1
//        plainBuffer.putUInt16(7600); // Product Build 7600
//        byte[] reserved = {(byte)0x00, (byte)0x00, (byte)0x00};
//        plainBuffer.putRawBytes(reserved); // Reserved (3 bytes)
//        plainBuffer.putByte((byte)0x0F); // NTLM Revision Current
//        return plainBuffer;
//    }
//}
