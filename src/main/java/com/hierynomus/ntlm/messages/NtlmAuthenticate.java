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

import java.nio.charset.StandardCharsets;

import static com.hierynomus.ntlm.functions.NtlmFunctions.unicode;

/**
 * [MS-NLMP].pdf 2.2.1.3 AUTHENTICATE_MESSAGE
 */
public class NtlmAuthenticate extends NtlmPacket {
    private static byte[] EMPTY = new byte[0];

    private byte[] lmResponse;
    private byte[] ntResponse;
    private byte[] userName;
    private byte[] domainName;
    private byte[] workstation;
    private byte[] encryptedRandomSessionKey;
    private long negotiateFlags;

    public NtlmAuthenticate(
            byte[] lmResponse, byte[] ntResponse,
            String userName, String domainName, String workstation,
            byte[] encryptedRandomSessionKey, long negotiateFlags
    ) {
        super();
        this.lmResponse = ensureNotNull(lmResponse);
        this.ntResponse = ensureNotNull(ntResponse);
        this.userName = ensureNotNull(userName);
        this.domainName = ensureNotNull(domainName);
        this.workstation = ensureNotNull(workstation);
        this.encryptedRandomSessionKey = ensureNotNull(encryptedRandomSessionKey);
        this.negotiateFlags = negotiateFlags;
    }

    @Override
    public void write(Buffer.PlainBuffer buffer) {
        buffer.putString("NTLMSSP\0", StandardCharsets.UTF_8); // Signature (8 bytes)
        buffer.putUInt32(0x03); // MessageType (4 bytes)

        int offset = 80; // for the offset

        offset = writeOffsettedByteArrayFields(buffer, lmResponse, offset); // LmChallengeResponseFields (8 bytes)
        offset = writeOffsettedByteArrayFields(buffer, ntResponse, offset); // NtChallengeResponseFields (8 bytes)
        offset = writeOffsettedByteArrayFields(buffer, domainName, offset); // DomainNameFields (8 bytes)
        offset = writeOffsettedByteArrayFields(buffer, userName, offset); // UserNameFields (8 bytes)
        offset = writeOffsettedByteArrayFields(buffer, workstation, offset); // WorkstationFields (8 bytes)
        if (EnumWithValue.EnumUtils.isSet(negotiateFlags, NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_KEY_EXCH)) {
            offset = writeOffsettedByteArrayFields(buffer, encryptedRandomSessionKey, offset);
        } else {
            offset = writeOffsettedByteArrayFields(buffer, EMPTY, offset);
        }

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
        buffer.putRawBytes(workstation);
        buffer.putRawBytes(encryptedRandomSessionKey);
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

    private int writeOffsettedByteArrayFields(Buffer.PlainBuffer buffer, byte[] array, int offset) {
        byte[] _array = array != null ? array : EMPTY;
        buffer.putUInt16(_array.length); // ArrayLen
        buffer.putUInt16(_array.length); // ArrayMaxLen
        buffer.putUInt32(offset); // ArrayOffset
        return offset + _array.length;
    }


    private byte[] ensureNotNull(byte[] possiblyNull) {
        return possiblyNull != null ? possiblyNull : EMPTY;
    }

    private byte[] ensureNotNull(String possiblyNull) {
        return possiblyNull != null ? unicode(possiblyNull) : EMPTY;
    }
}
