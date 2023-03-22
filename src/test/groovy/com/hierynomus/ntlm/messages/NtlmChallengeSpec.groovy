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

import com.hierynomus.protocol.commons.buffer.Buffer
import com.hierynomus.protocol.commons.buffer.Endian
import spock.lang.Specification

class NtlmChallengeSpec extends Specification implements SampleMessages {

  def "Should correctly decode NTLMv1 NtlmChallenge message"() {
    given:
    def m = new NtlmChallenge()

    when:
    m.read(new Buffer.PlainBuffer(ntlmV1ChallengeMessageBytes, Endian.LE))

    then:
    m.negotiateFlags == ntlmV1NegotiationFlags
    m.serverChallenge == serverChallenge
    m.version == windowsVersion
    m.targetName == targetName
    m.targetInfo == null
  }

  def "Should correctly decode NTLMv1 with ClientChallenge NtlmChallenge message"() {
    given:
    def m = new NtlmChallenge()

    when:
    m.read(new Buffer.PlainBuffer(ntlmV1WithClientChallengeChallengeMessageBytes, Endian.LE))

    then:
    m.negotiateFlags == ntlmV1WithClientChallengeNegotiationFlags
    m.serverChallenge == serverChallenge
    m.version == windowsVersion
    m.targetName == targetName
    m.targetInfo == null
  }

  def "Should correctly decode NTLMv2 NtlmChallenge message"() {
    given:
    def m = new NtlmChallenge()

    when:
    m.read(new Buffer.PlainBuffer(ntlmV2ChallengeMessageBytes, Endian.LE))

    then:
    m.negotiateFlags == ntlmV2NegotiationFlags
    m.serverChallenge == serverChallenge
    m.version == windowsVersion
    m.targetName == targetName
    m.targetInfo.getAvPairObject(AvId.MsvAvNbComputerName) == "Server" // NetBIOS Server name
    m.targetInfo.getAvPairObject(AvId.MsvAvNbDomainName) == "Domain" // NetBIOS Domain name
  }
}
