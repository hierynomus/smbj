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

import com.hierynomus.protocol.commons.buffer.Buffer
import com.hierynomus.protocol.commons.buffer.Endian
import spock.lang.Specification

class BufferByteChunkProviderSpec extends Specification {

  def buffer = new Buffer.PlainBuffer(Endian.BE)
  def provider = new BufferByteChunkProvider(buffer)

  def "empty provider should have no available bytes"() {
    expect:
    !provider.isAvailable()
    provider.bytesLeft() == 0
  }

  def "should have right number of bytes available"() {
    given:
    buffer.putUInt64(0xffffffff)

    expect:
    provider.bytesLeft() == 8
    provider.isAvailable()
  }

  def "should read available bytes into array"() {
    given:
    buffer.putUInt64(0x0fffffffffffffffL)
    def chunk = new byte[8]

    when:
    provider.getChunk(chunk)

    then:
    chunk == [0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff] as byte[]
    provider.bytesLeft() == 0
    !provider.isAvailable()
  }

  def "should read partial chunk if nothing left"() {
    given:
    buffer.putUInt32(0xffffffff)
    def chunk = new byte[8]

    when:
    provider.getChunk(chunk)

    then:
    chunk == [0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0] as byte[]
    provider.bytesLeft() == 0
    !provider.isAvailable()
  }

  def "should not fail if nothing to read"() {
    given:
    def chunk = new byte[8]

    when:
    provider.getChunk(chunk)

    then:
    chunk == [0] * 8 as byte[]
  }
}
