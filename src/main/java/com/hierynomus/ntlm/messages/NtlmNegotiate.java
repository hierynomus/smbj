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

import com.hierynomus.protocol.commons.Charsets;
import com.hierynomus.protocol.commons.buffer.Buffer;

import java.util.EnumSet;
import java.util.Set;

import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.*;
import static com.hierynomus.ntlm.functions.NtlmFunctions.unicode;
import static com.hierynomus.ntlm.messages.Utils.*;

/**
 * [MS-NLMP].pdf 2.2.1.1 NEGOTIATE_MESSAGE
 */
public class NtlmNegotiate extends NtlmPacket {
    public static final long DEFAULT_FLAGS = EnumUtils.toLong(EnumSet.of(
        NTLMSSP_NEGOTIATE_NTLM,
        NTLMSSP_NEGOTIATE_VERSION,
        NTLMSSP_NEGOTIATE_UNICODE));

    private long flags;
    private byte[] domain;
    private byte[] workstation;

    public NtlmNegotiate(Set<NtlmNegotiateFlag> flags, String domain, String workstation) {
        this.flags = EnumUtils.toLong(flags) | DEFAULT_FLAGS;
        this.domain = domain == null ? new byte[0] : unicode(domain);
        this.workstation = workstation == null ? new byte[0] : unicode(workstation);
    }

    public void write(Buffer.PlainBuffer buffer) {
        buffer.putString("NTLMSSP\0", Charsets.UTF_8); // Signature (8 bytes)
        buffer.putUInt32(0x01); // MessageType (4 bytes)

        // Write the negotiateFlags as Big Endian, as this is a byte[] in the spec and not an integral value
        buffer.putUInt32(flags); // NegotiateFlags (4 bytes)

        int offset = 0x20;
        // DomainNameFields (8 bytes)
        offset = writeOffsettedByteArrayFields(buffer, domain, offset);
        // WorkstationFields (8 bytes)
        offset = writeOffsettedByteArrayFields(buffer, workstation, offset);

        // DomainName (variable)
        buffer.putRawBytes(domain);
        // Workstation (variable)
        buffer.putRawBytes(workstation);
    }
}
