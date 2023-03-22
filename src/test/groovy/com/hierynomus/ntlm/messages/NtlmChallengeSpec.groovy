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
