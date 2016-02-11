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
package com.hierynomus.ntlm.messages

import com.hierynomus.protocol.commons.EnumWithValue
import spock.lang.Specification
import spock.lang.Unroll

@Unroll
class NtlmNegotiateFlagTest extends Specification {

    def "flag #flag should be set in flags #flags"() {
        given:

        expect:
        EnumWithValue.EnumUtils.isSet(flags, flag)

        where:
        flags       | flag
        0xa0880205L | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_56
        0xa0880205L | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_128
        0xa0880205L | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_TARGET_INFO
        0xa0880205L | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        0xa0880205L | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_NTLM
        0xa0880205L | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_NTLM
        0xa0880205L | NtlmNegotiateFlag.NTLMSSP_REQUEST_TARGET
        0xa0880205L | NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_UNICODE

    }
}
