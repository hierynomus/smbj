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
package com.hierynomus.security.jce.derivationfunction

import spock.lang.Specification
import org.codehaus.groovy.runtime.EncodingGroovyMethods

class KDFCounterHMacSHA256Spec extends Specification {

  def "KDF Counter tests"() {
    when:
        def df = new KDFCounterHMacSHA256()
        def params = new CounterDerivationParameters(EncodingGroovyMethods.decodeHex(seed), EncodingGroovyMethods.decodeHex(suffix), 32)
        df.init(params)
        byte[] derived = new byte[16];
        df.generateBytes(derived, 0, derived.length)

    then:
        derived == EncodingGroovyMethods.decodeHex(expectedResults)

    where:
        seed << ["05748462F987037190DEF58A165E3678", "05748462F987037190DEF58A165E3678", "C3ACFDC1B070770A8DDAB9740DA29B79"]
        suffix << ["534D425369676E696E674B6579000043F965A710069C1CEC7D79469C0FDE7143FB350599997C65D2B5D65B40DED490C0E13BA9F5822D2619BFEB08873909926F4BBE455321DC4C151A46B47718421F00000080" , "534D424332534369706865724B6579000043F965A710069C1CEC7D79469C0FDE7143FB350599997C65D2B5D65B40DED490C0E13BA9F5822D2619BFEB08873909926F4BBE455321DC4C151A46B47718421F00000080", "534D425369676E696E674B65790000FE8742AB31DC7A88DF45BCA328875D079E597CF711D3AFB397AF32422E9BD8541C1F0E1D665646B56A141BE700351C35FB7426F9946F22271DE0B4EDFAFBC11E00000080"]
        expectedResults << ["E4F496372BB7FBA2BFCAE08AA07C9C16", "17566BCB45012959EBE074736B0EBD79", "14595AE1720357BBA5B22084041E27E9"]
  }
}