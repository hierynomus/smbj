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
public class NtlmChallengeResponse extends NtlmPacket {

    byte[] lmResponse;
    byte[] ntResponse;
    String userName;
    String domainName;
    String workStation;
    byte[] encryptedRandomSessionKey;
    long negotiateFlags = NtlmNegotiate.DEFAULT_FLAGS;

    public NtlmChallengeResponse(
            byte[] lmResponse, byte[] ntResponse,
            String userName, String domainName, String workStation,
            byte[] encryptedRandomSessionKey, long negotiateFlags
    ) {
        super();
        this.lmResponse = lmResponse;
        this.ntResponse = ntResponse;
        this.userName = userName;
        this.domainName = domainName;
        this.workStation = workStation;
        this.encryptedRandomSessionKey = encryptedRandomSessionKey;
        this.negotiateFlags = negotiateFlags;
    }

    public void write(Buffer.PlainBuffer buffer) {
        buffer.putString("NTLMSSP\0", Charset.forName("UTF-8")); // Signature (8 bytes)
        buffer.putUInt32(0x03); // MessageType (4 bytes)

        int offset = 80; // for the offset

        byte[] _lmResponse = (lmResponse == null) ? new byte[0] : lmResponse;
        buffer.putUInt16(_lmResponse.length); // Len
        buffer.putUInt16(_lmResponse.length); // Max Len
        buffer.putUInt32(offset);
        offset += _lmResponse.length;

        byte[] _ntResponse = (ntResponse == null) ? new byte[0] : ntResponse;
        buffer.putUInt16(_ntResponse.length); // Len
        buffer.putUInt16(_ntResponse.length); // Max Len
        buffer.putUInt32(offset);
        offset += _ntResponse.length;

        byte[] _domainName = (domainName == null) ? new byte[0] : unicode(domainName);
        buffer.putUInt16(_domainName.length); // Len
        buffer.putUInt16(_domainName.length); // Max Len
        buffer.putUInt32(offset);
        offset += _domainName.length;

        byte[] _userName = (userName == null) ? new byte[0] : unicode(userName);
        buffer.putUInt16(_userName.length); // Len
        buffer.putUInt16(_userName.length); // Max Len
        buffer.putUInt32(offset);
        offset += _userName.length;

        byte[] _workStation = (workStation == null) ? new byte[0] : unicode(workStation);
        buffer.putUInt16(_workStation.length); // Len
        buffer.putUInt16(_workStation.length); // Max Len
        buffer.putUInt32(offset);
        offset += _workStation.length;

        byte[] _sessionKey = (encryptedRandomSessionKey == null) ? new byte[0] : encryptedRandomSessionKey;
        buffer.putUInt16(_sessionKey.length); // Len
        buffer.putUInt16(_sessionKey.length); // Max Len
        buffer.putUInt32(offset);
        offset += _sessionKey.length;

        buffer.putUInt32(negotiateFlags); // Flags

        if (EnumWithValue.EnumUtils.isSet(negotiateFlags, NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_VERSION)) {
            buffer.putRawBytes(getVersion());
        }

        // MIC
        // TODO Set MIC to HMAC_MD5(ExportedSessionKey, ConcatenationOf( CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE))
        byte[] MIC = new byte[16];
        buffer.putRawBytes(MIC);

        buffer.putRawBytes(_lmResponse);
        buffer.putRawBytes(_ntResponse);
        buffer.putRawBytes(_domainName);
        buffer.putRawBytes(_userName);
        buffer.putRawBytes(_workStation);
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
}
