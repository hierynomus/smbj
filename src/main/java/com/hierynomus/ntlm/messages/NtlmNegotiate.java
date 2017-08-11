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

import com.hierynomus.protocol.commons.buffer.Buffer;

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;

import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.*;

/**
 * [MS-NLMP].pdf 2.2.1.1 NEGOTIATE_MESSAGE
 */
public class NtlmNegotiate extends NtlmPacket {
    public static final long DEFAULT_FLAGS = EnumUtils.toLong(EnumSet.of(
        NTLMSSP_NEGOTIATE_56,
        NTLMSSP_NEGOTIATE_128,
        NTLMSSP_NEGOTIATE_TARGET_INFO,
        NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
        NTLMSSP_NEGOTIATE_SIGN,
        NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
        NTLMSSP_NEGOTIATE_KEY_EXCH,
        NTLMSSP_NEGOTIATE_NTLM,
        NTLMSSP_NEGOTIATE_NTLM,
        NTLMSSP_REQUEST_TARGET,
        NTLMSSP_NEGOTIATE_UNICODE));

    private long flags = DEFAULT_FLAGS;

    public void write(Buffer.PlainBuffer buffer) {
        buffer.putString("NTLMSSP\0", StandardCharsets.UTF_8); // Signature (8 bytes)
        buffer.putUInt32(0x01); // MessageType (4 bytes)

        // Write the negotiateFlags as Big Endian, as this is a byte[] in the spec and not an integral value
        buffer.putUInt32(flags); // NegotiateFlags (4 bytes)

        // DomainNameFields (8 bytes)
        buffer.putUInt16(0x0); // DomainNameLen (2 bytes)
        buffer.putUInt16(0x0); // DomainNameMaxLen (2 bytes)
        buffer.putUInt32(0x0); // DomainNameBufferOffset (4 bytes)
        // WorkstationFields (8 bytes)
        buffer.putUInt16(0x0); // WorkstationLen (2 bytes)
        buffer.putUInt16(0x0); // WorkstationMaxLen (2 bytes)
        buffer.putUInt32(0x0); // WorkstationBufferOffset (4 bytes)
    }
}
