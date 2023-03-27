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
package com.hierynomus.ntlm.functions

import com.hierynomus.msdtyp.FileTime
import com.hierynomus.msdtyp.MsDataTypes
import com.hierynomus.ntlm.messages.AvId
import com.hierynomus.ntlm.messages.NtlmChallenge
import com.hierynomus.ntlm.messages.TargetInfo
import com.hierynomus.protocol.commons.buffer.Buffer
import com.hierynomus.protocol.commons.buffer.Endian
import com.hierynomus.security.bc.BCSecurityProvider
import com.hierynomus.security.jce.JceSecurityProvider
import com.hierynomus.test.PredictableRandom
import org.apache.tools.ant.taskdefs.Tar
import org.bouncycastle.jce.provider.BouncyCastleProvider
import spock.lang.Specification
import spock.lang.Unroll

import java.security.SecureRandom

class NtlmFunctionsSpec extends Specification {

  static Random random = new PredictableRandom()
  static
  def providers = [new JceSecurityProvider(), new JceSecurityProvider(new BouncyCastleProvider()), new BCSecurityProvider()]

  @Unroll
  def "should correctly determine LMOWFv1 LM hash"() {
    given:
    def f = new NtlmV1Functions(random, provider)
    expect:
    f.LMOWFv1("admin", null, null) == [0xf0, 0xd4, 0x12, 0xbd, 0x76, 0x4f, 0xfe, 0x81, 0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee] as byte[]

    where:
    provider << providers
  }

  @Unroll
  def "should correctly determine RC4 Encryption"() {
    expect:
    NtlmFunctions.rc4k(provider, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0f, 0x10] as byte[], "Hello".getBytes("UTF-8")) == [0x65, 0x55, 0x5a, 0x25, -0x4a] as byte[]

    where:
    provider << providers
  }

  @Unroll
  def "Should give correct outcome for MS-NLMP examples NTLMv1 (4.2.2.1)"() {
    given:
    def f = new NtlmV1Functions(random, provider)

    expect:
    f.LMOWFv1("Password", "User", "Domain") == [0xe5, 0x2c, 0xac, 0x67, 0x41, 0x9a, 0x9a, 0x22, 0x4a, 0x3b, 0x10, 0x8f, 0x3f, 0xa6, 0xcb, 0x6d] as byte[]
    f.NTOWFv1("Password", "User", "Domain") == [0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca, 0xb6, 0x82, 0x4e, 0xe7, 0xc3, 0x0f, 0xd8, 0x52] as byte[]

    where:
    provider << providers
  }

  @Unroll
  def "Should give the correct outcome for MS-NLMP examples NTLMv2 (4.2.4.1)"() {
    given:
    def f = new NtlmV2Functions(random, provider)

    expect:
    f.NTOWFv2("Password", "User", "Domain") == [0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93, 0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0, 0x2e, 0x3f] as byte[]
    f.LMOWFv2("Password", "User", "Domain") == [0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93, 0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0, 0x2e, 0x3f] as byte[]

    where:
    provider << providers
  }

  @Unroll
  def "Should correctly calculate NTResponse temp variable for NS-NLMP examples NTLMv2 (4.2.4.1.3)"() {
    given:
    def f = new NtlmV2Functions(random, provider)
    def targetInfo = new TargetInfo().readFrom(new Buffer.PlainBuffer([0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00,
                                                                       0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00,
                                                                       0x00, 0x00, 0x00, 0x00] as byte[], Endian.LE))

    expect:
    f.ntResponseTemp([0xaa]*8 as byte[], 0, targetInfo) == [0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                            0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00,
                                                            0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00,
                                                            0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00,
                                                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] as byte[]

    where:
    provider << providers
  }

  @Unroll
  def "Should give correct ComputedResponse for MS-NLMP examples NTLMv2 (4.2.4.2.1 / 4.2.4.2.2 / 4.2.4.2.3)"() {
    given:
    def f = new NtlmV2Functions(random, provider)
    random.init([0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55] as byte[])
    def targetInfo = new TargetInfo()
    targetInfo.putAvPairObject(AvId.MsvAvNbDomainName, "Domain")
    targetInfo.putAvPairObject(AvId.MsvAvNbComputerName, "Server")
    def serverChallenge = new NtlmChallenge()
    serverChallenge.serverChallenge = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef] as byte[]

    when:
    def computedResponse = f.computeResponse("User", "Domain", "Password".toCharArray(), serverChallenge, 0, targetInfo)

    then:
    computedResponse.getLmResponse() == [0x86, 0xc3, 0x50, 0x97, 0xac, 0x9c, 0xec, 0x10, 0x25, 0x54, 0x76, 0x4a, 0x57, 0xcc, 0xcc, 0x19, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa] as byte[]
    computedResponse.getSessionBaseKey() == [0x8d, 0xe4, 0x0c, 0xca, 0xdb, 0xc1, 0x4a, 0x82, 0xf1, 0x5c, 0xb0, 0xad, 0x0d, 0xe9, 0x5c, 0xa3] as byte[]
    computedResponse.getNtResponse()[0..15] == [0x68, 0xcd, 0x0a, 0xb8, 0x51, 0xe5, 0x1c, 0x96, 0xaa, 0xbc, 0x92, 0x7b, 0xeb, 0xef, 0x6a, 0x1c] as byte[]

    where:
    provider << [new JceSecurityProvider()]
    // TODO note the BC SecurityProviders seem to be giving different results.
  }
}
