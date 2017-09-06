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

import com.hierynomus.ntlm.messages.NtlmNegotiate
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.protocol.commons.buffer.Buffer
import com.hierynomus.protocol.commons.buffer.Endian
import org.bouncycastle.asn1.microsoft.MicrosoftObjectIdentifiers
import spock.lang.Specification

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

    when:
    new NtlmNegotiate().write(ntlmBuffer)
    initToken.addSupportedMech(MicrosoftObjectIdentifiers.microsoft.branch("2.2.10"))
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
}
