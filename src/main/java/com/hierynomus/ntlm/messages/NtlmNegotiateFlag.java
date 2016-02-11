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
package com.hierynomus.ntlm.messages;

import com.hierynomus.protocol.commons.EnumWithValue;

/**
 * [MS-NLMP].pdf 2.2.2.5 NEGOTIATE
 */
public enum NtlmNegotiateFlag implements EnumWithValue<NtlmNegotiateFlag> {
    // Byte 1
    NTLMSSP_NEGOTIATE_56(0x80000000L),
    NTLMSSP_NEGOTIATE_KEY_EXCH(0x40000000L),
    NTLMSSP_NEGOTIATE_128(0x20000000L),
    NTLMSSP_NEGOTIATE_VERSION(0x2000000L),
    // Byte 2
    NTLMSSP_NEGOTIATE_TARGET_INFO(0x800000L),
    NTLMSSP_REQUEST_NON_NT_SESSION_KEY(0x400000L),
    NTLMSSP_NEGOTIATE_IDENTIFY(0x100000L),
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY(0x80000L),
    NTLMSSP_TARGET_TYPE_SERVER(0x20000L),
    NTLMSSP_TARGET_TYPE_DOMAIN(0x10000L),
    // Byte 3
    NTLMSSP_NEGOTIATE_ALWAYS_SIGN(0x8000L),
    NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED(0x2000L),
    NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED(0x1000L),
    ANONYMOUS(0x800L),
    NTLMSSP_NEGOTIATE_NTLM(0x200L),
    // Byte 4
    NTLMSSP_NEGOTIATE_LM_KEY(0x80L),
    NTLMSSP_NEGOTIATE_DATAGRAM(0x40L),
    NTLMSSP_NEGOTIATE_SEAL(0x20L),
    NTLMSSP_NEGOTIATE_SIGN(0x10L),
    NTLMSSP_REQUEST_TARGET(0x04L),
    NTLM_NEGOTIATE_OEM(0x02L),
    NTLMSSP_NEGOTIATE_UNICODE(0x01);

    private long value;

    NtlmNegotiateFlag(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
