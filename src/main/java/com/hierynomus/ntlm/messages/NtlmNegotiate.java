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

import static com.hierynomus.ntlm.messages.Utils.EMPTY;
import static com.hierynomus.ntlm.messages.Utils.writeOffsettedByteArrayFields;

import com.hierynomus.ntlm.functions.NtlmFunctions;
import com.hierynomus.protocol.commons.Charsets;
import com.hierynomus.protocol.commons.buffer.Buffer;

import java.util.Set;

import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.*;

/**
 * [MS-NLMP].pdf 2.2.1.1 NEGOTIATE_MESSAGE
 */
public class NtlmNegotiate extends NtlmMessage {

    private byte[] domain;
    private byte[] workstation;
    private boolean omitVersion;

    public NtlmNegotiate(Set<NtlmNegotiateFlag> flags, String domain, String workstation, WindowsVersion version, boolean omitVersion) {
        super(flags, version);
        this.domain = domain != null ? NtlmFunctions.oem(domain) : EMPTY;
        this.workstation = workstation != null ? NtlmFunctions.oem(workstation) : EMPTY;
        this.omitVersion = omitVersion;
    }

    public void write(Buffer.PlainBuffer buffer) {
        buffer.putString("NTLMSSP\0", Charsets.UTF_8); // Signature (8 bytes)
        buffer.putUInt32(0x01); // MessageType (4 bytes)

        // Write the negotiateFlags as Big Endian, as this is a byte[] in the spec and
        // not an integral value
        buffer.putUInt32(EnumUtils.toLong(negotiateFlags)); // NegotiateFlags (4 bytes)

        int offset = 0x20;
        if (!omitVersion) {
            offset += 8; // Version (8 bytes)
        }

        if (negotiateFlags.contains(NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED)) {
            // DomainNameFields (8 bytes)
            offset = writeOffsettedByteArrayFields(buffer, domain, offset);
        } else {
            buffer.putUInt16(0); // DomainNameLen (2 bytes)
            buffer.putUInt16(0); // DomainNameMaxLen (2 bytes)
            buffer.putUInt32(0); // DomainNameBufferOffset (4 bytes)
        }

        if (negotiateFlags.contains(NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED)) {
            // WorkstationFields (8 bytes)
            offset = writeOffsettedByteArrayFields(buffer, workstation, offset);
        } else {
            buffer.putUInt16(0); // WorkstationLen (2 bytes)
            buffer.putUInt16(0); // WorkstationMaxLen (2 bytes)
            buffer.putUInt32(0); // WorkstationBufferOffset (4 bytes)
        }

        // if `omitVersion`, omit this field, because some implementations (e.g. Windows
        // 2000) don't like it
        if (!omitVersion && negotiateFlags.contains(NTLMSSP_NEGOTIATE_VERSION)) {
            version.writeTo(buffer); // Version (8 bytes)
        } else if (!omitVersion) {
            buffer.putUInt64(0); // Reserved (8 bytes)
        }

        buffer.putRawBytes(domain); // DomainName (variable)
        buffer.putRawBytes(workstation); // Workstation (variable)
    }

    @Override
    public String toString() {
        return "NtlmNegotiate{\n" +
                "  domain='" + NtlmFunctions.oem(domain) + "'',\n" +
                "  workstation='" + NtlmFunctions.oem(workstation) + "',\n" +
                "  negotiateFlags=" + negotiateFlags + ",\n" +
                "  version=" + version + "\n" +
                "}";
    }

}
