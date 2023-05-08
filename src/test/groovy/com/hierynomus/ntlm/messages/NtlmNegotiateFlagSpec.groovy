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
package com.hierynomus.ntlm.messages

import com.hierynomus.protocol.commons.EnumWithValue
import spock.lang.Specification
import spock.lang.Unroll

@Unroll
class NtlmNegotiateFlagSpec extends Specification {

  def "flag #flag should be set for flags #flags"() {
    given:
    expect:
    EnumWithValue.EnumUtils.isSet(flags, flag)
    where:
    flag                                                         | flags
    NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_56                       | 0b10000000000000000000000000000000
    NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_KEY_EXCH                 | 0b01000000000000000000000000000000
    NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_128                      | 0b00100000000000000000000000000000
    NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_VERSION                  | 0b00000010000000000000000000000000
    NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_TARGET_INFO              | 0b00000000100000000000000000000000
    NtlmNegotiateFlag.NTLMSSP_REQUEST_NON_NT_SESSION_KEY         | 0b00000000010000000000000000000000
    NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_IDENTIFY                 | 0b00000000000100000000000000000000
    NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | 0b00000000000010000000000000000000
    NtlmNegotiateFlag.NTLMSSP_TARGET_TYPE_SERVER                 | 0b00000000000000100000000000000000
    NtlmNegotiateFlag.NTLMSSP_TARGET_TYPE_DOMAIN                 | 0b00000000000000010000000000000000
    NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_ALWAYS_SIGN              | 0b00000000000000001000000000000000
    NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED | 0b00000000000000000010000000000000
    NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED      | 0b00000000000000000001000000000000
    NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_ANONYMOUS                | 0b00000000000000000000100000000000
    NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_NTLM                     | 0b00000000000000000000001000000000
    NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_LM_KEY                   | 0b00000000000000000000000010000000
    NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_DATAGRAM                 | 0b00000000000000000000000001000000
    NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SEAL                     | 0b00000000000000000000000000100000
    NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SIGN                     | 0b00000000000000000000000000010000
    NtlmNegotiateFlag.NTLMSSP_REQUEST_TARGET                     | 0b00000000000000000000000000000100
    NtlmNegotiateFlag.NTLM_NEGOTIATE_OEM                         | 0b00000000000000000000000000000010
    NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_UNICODE                  | 0b00000000000000000000000000000001
  }

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
