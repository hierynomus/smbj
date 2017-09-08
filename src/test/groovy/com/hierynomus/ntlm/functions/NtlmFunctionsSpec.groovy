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
    expect:
    new NtlmFunctions(random, provider).LMOWFv1("admin", null, null) == [0xf0, 0xd4, 0x12, 0xbd, 0x76, 0x4f, 0xfe, 0x81, 0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee] as byte[]

    where:
    provider << providers
  }

  @Unroll
  def "should correctly determine RC4 Encryption"() {
    given:
    def f = new NtlmFunctions(random, provider)

    expect:
    f.encryptRc4([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0f, 0x10] as byte[], "Hello".getBytes("UTF-8")) == [0x65, 0x55, 0x5a, 0x25, -0x4a] as byte[]

    where:
    provider << providers
  }
}
