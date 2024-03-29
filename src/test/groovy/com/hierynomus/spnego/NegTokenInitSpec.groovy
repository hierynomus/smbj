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
package com.hierynomus.spnego

import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier
import com.hierynomus.ntlm.messages.NtlmNegotiate
import com.hierynomus.ntlm.messages.WindowsVersion
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.protocol.commons.buffer.Buffer
import com.hierynomus.protocol.commons.buffer.Endian
import spock.lang.Specification

import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_128
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_56
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_ALWAYS_SIGN
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_KEY_EXCH
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_NTLM
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SIGN
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_TARGET_INFO
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_UNICODE
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_REQUEST_TARGET
import static com.hierynomus.ntlm.messages.WindowsVersion.NtlmRevisionCurrent.NTLMSSP_REVISION_W2K3
import static com.hierynomus.ntlm.messages.WindowsVersion.ProductMajorVersion.WINDOWS_MAJOR_VERSION_6
import static com.hierynomus.ntlm.messages.WindowsVersion.ProductMinorVersion.WINDOWS_MINOR_VERSION_1

class NegTokenInitSpec extends Specification {

  def "should correctly decode GSS-API negInitToken"() {
    given:
    def bytes = getClass().getClassLoader().getResourceAsStream("spnego/negTokenInit_resp").bytes
    def buffer = new Buffer.PlainBuffer(bytes, Endian.LE)

    when:
    def negTokenInit = new NegTokenInit().read(buffer)

    then:
    negTokenInit.supportedMechTypes.size() == 2
  }

  def "should correctly encode ntlm choice negInitToken"() {
    given:
    def initToken = new NegTokenInit()
    def ntlmBuffer = new Buffer.PlainBuffer(Endian.LE)
    def spnegoBuffer = new Buffer.PlainBuffer(Endian.LE)
    def flags = EnumSet.of(NTLMSSP_NEGOTIATE_56,
      NTLMSSP_NEGOTIATE_128,
      NTLMSSP_NEGOTIATE_TARGET_INFO,
      NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
      NTLMSSP_NEGOTIATE_SIGN,
      NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
      NTLMSSP_NEGOTIATE_KEY_EXCH,
      NTLMSSP_NEGOTIATE_NTLM,
      NTLMSSP_REQUEST_TARGET,
      NTLMSSP_NEGOTIATE_UNICODE)

    when:
    new NtlmNegotiate(flags, "", "", new WindowsVersion(WINDOWS_MAJOR_VERSION_6, WINDOWS_MINOR_VERSION_1, 7600, NTLMSSP_REVISION_W2K3), true).write(ntlmBuffer)
    initToken.addSupportedMech(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.2.10"))
    initToken.setMechToken(ntlmBuffer.compactData)
    initToken.write(spnegoBuffer)

    then:
    spnegoBuffer.compactData == getClass().getClassLoader().getResourceAsStream("spnego/negTokenInit_ntlm").bytes
  }

  def "should correctly decode GSS-API negInitToken with a larger(unsigned) byte"() {
    given:
    String hexString1 = "6082013c06062b0601050502a08201303082012ca01a3018060a2b06010401823702021e060a2b06010401823702020aa282010c048201084e45474f45585453010000000000000060000000700000006466954c2f2bb9c567e8b6f9cf6c8318b5f56f2061bab21c8818ac2c52ea9f43caea9320fbc165803d3742c77cc398ee0000000000000000600000000100000000000000000000005c33530deaf90d4db2ec4ae3786ec3084e45474f45585453030000000100000040000000980000006466954c2f2bb9c567e8b6f9cf6c83185c33530deaf90d4db2ec4ae3786ec30840000000580000003056a05430523027802530233121301f06035504031318546f6b656e205369676e696e67205075626c6963204b65793027802530233121301f06035504031318546f6b656e205369676e696e67205075626c6963204b6579"
    byte[] bytes1 = ByteArrayUtils.parseHex(hexString1)

    when:
    def negTokenInit = new NegTokenInit().read(bytes1)

    then:
    negTokenInit.supportedMechTypes.size() == 2
    negTokenInit.mechToken == ByteArrayUtils.parseHex("4e45474f45585453010000000000000060000000700000006466954c2f2bb9c567e8b6f9cf6c8318b5f56f2061bab21c8818ac2c52ea9f43caea9320fbc165803d3742c77cc398ee0000000000000000600000000100000000000000000000005c33530deaf90d4db2ec4ae3786ec3084e45474f45585453030000000100000040000000980000006466954c2f2bb9c567e8b6f9cf6c83185c33530deaf90d4db2ec4ae3786ec30840000000580000003056a05430523027802530233121301f06035504031318546f6b656e205369676e696e67205075626c6963204b65793027802530233121301f06035504031318546f6b656e205369676e696e67205075626c6963204b6579")
  }
  def b = [96, 64, 6, 6, 43, 6, 1, 5, 5, 2, -96, 54, 48, 52, -96, 14, 48, 12, 6, 10, 43, 6, 1, 4, 1, -126, 55, 2, 2, 10, -94, 34, 4, 32, 78, 84, 76, 77, 83, 83, 80, 0, 1, 0, 0, 0, 0x11, -126, -120, -30, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0]
  def "should correctly decode GSS-API negTokenInit with a negHint"() {
    given:
    String hexString1 = "605606062b0601050502a04c304aa02b302906092a864886f71201020206052b0501050206092a864882f712010202060a2b06010401823702020aa31b3019a0171b15686f73742f70757370646973696c6f6e30312d3340"
    byte[] bytes1 = ByteArrayUtils.parseHex(hexString1)

    when:
    def negTokenInit = new NegTokenInit2().read(bytes1)

    then:
    negTokenInit.supportedMechTypes.size() == 4
    negTokenInit.mechToken == null
  }

}
