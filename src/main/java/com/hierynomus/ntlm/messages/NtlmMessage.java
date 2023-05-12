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

import java.util.EnumSet;
import java.util.Set;

import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.*;

class NtlmMessage extends NtlmPacket {
    protected static Set<NtlmNegotiateFlag> DEFAULT_FLAGS = EnumSet.of(
            NTLMSSP_NEGOTIATE_NTLM,
            NTLMSSP_NEGOTIATE_UNICODE);

    protected Set<NtlmNegotiateFlag> negotiateFlags;
    protected WindowsVersion version;

    protected NtlmMessage(Set<NtlmNegotiateFlag> negotiateFlags, WindowsVersion version) {
        this.negotiateFlags = EnumSet.copyOf(negotiateFlags);
        this.negotiateFlags.addAll(DEFAULT_FLAGS);
        this.version = version;
    }
}
