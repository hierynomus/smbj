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

import com.hierynomus.security.bc.BCSecurityProvider
import com.hierynomus.security.jce.JceSecurityProvider
import org.bouncycastle.jce.provider.BouncyCastleProvider
import spock.lang.Specification
import spock.lang.Unroll

import java.security.SecureRandom

class NtlmFunctionsSpec extends Specification {

  static SecureRandom random = new SecureRandom()
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
}
