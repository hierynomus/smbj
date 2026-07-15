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
package com.hierynomus.smbj.io

import spock.lang.Specification

class InputStreamByteChunkProviderSpec extends Specification {

  def "should close underlying input stream when closing provider"() {
    given:
    def is = Mock(InputStream)
    def provider = new InputStreamByteChunkProvider(is)

    when:
    provider.close()

    then:
    1 * is.close()
  }

  def "isAvailable should not rely on InputStream.available() estimate"() {
    given: "an InputStream whose available() always returns 0 despite having data"
    def underlying = new ByteArrayInputStream([1, 2, 3, 4, 5, 6] as byte[]) {
      @Override
      int available() { return 0 }
    }
    def provider = new InputStreamByteChunkProvider(underlying)

    expect: "provider reports data is available even though available() returns 0"
    provider.isAvailable()

    when: "all data is read"
    def chunk = new byte[6]
    provider.prepareWrite(6)
    provider.getChunk(chunk)

    then: "provider correctly reports no more data"
    !provider.isAvailable()
  }

  def "bytesLeft should reflect peeked byte immediately after isAvailable"() {
    given: "an InputStream whose available() always returns 0 despite having data"
    def underlying = new ByteArrayInputStream([1, 2, 3] as byte[]) {
      @Override
      int available() { return 0 }
    }
    def provider = new InputStreamByteChunkProvider(underlying)

    when: "isAvailable is called without a subsequent prepareWrite"
    def available = provider.isAvailable()

    then: "bytesLeft reflects the peeked data (as SMB2WriteRequest relies on)"
    available
    provider.bytesLeft() > 0
  }
}
