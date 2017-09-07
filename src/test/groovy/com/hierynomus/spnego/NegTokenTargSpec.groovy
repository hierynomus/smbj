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

import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.protocol.commons.buffer.Buffer
import com.hierynomus.protocol.commons.buffer.Endian
import spock.lang.Specification

class NegTokenTargSpec extends Specification {

  def "should parse negTokenTarg with ntlm challenge"() {
    given:
    def bytes = getClass().getClassLoader().getResourceAsStream("spnego/negTokenTarg_ntlmchallenge").bytes
    def buffer = new Buffer.PlainBuffer(bytes, Endian.LE)

    expect:
    println(ByteArrayUtils.printHex(bytes))
    def read = new NegTokenTarg().read(buffer)
    read.negotiationResult == BigInteger.ONE

  }
}
