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
import java.nio.ByteBuffer

class ByteBufferByteChunkProviderSpec extends Specification {

  def "should write 1 chunk to outputStream"() {
    given:
    def buffer = getBufferWithRandomData(ByteChunkProvider.CHUNK_SIZE)
    def checkBuff = buffer.duplicate()
    def provider = new ByteBufferByteChunkProvider(buffer)
    def baos = new ByteArrayOutputStream()

    when:
    provider.prepareWrite(ByteChunkProvider.CHUNK_SIZE)
    provider.writeChunk(baos)

    then:
    baos.toByteArray() == checkBuff.array()
    provider.offset == ByteChunkProvider.CHUNK_SIZE
    !provider.isAvailable()
  }

  def "should write part of chunk to outputStream"() {
    given:
    def buffer = getBufferWithRandomData(1024)
    def checkBuff = buffer.duplicate()
    def provider = new ByteBufferByteChunkProvider(buffer)
    def baos = new ByteArrayOutputStream()

    when:
    provider.prepareWrite(ByteChunkProvider.CHUNK_SIZE)
    provider.writeChunk(baos)

    then:
    baos.toByteArray() == checkBuff.array()
    provider.offset == 1024
    !provider.isAvailable()

  }

  def "should have available after writing first chunk"() {
    given:
    def buffer = getBufferWithRandomData(ByteChunkProvider.CHUNK_SIZE + 1)
    def provider = new ByteBufferByteChunkProvider(buffer)
    def baos = new ByteArrayOutputStream()

    when:
    provider.prepareWrite(ByteChunkProvider.CHUNK_SIZE)
    provider.writeChunk(baos)

    then:
    provider.offset == ByteChunkProvider.CHUNK_SIZE
    provider.isAvailable()

  }

  private def getBufferWithRandomData(int size) {
    def bytes = new byte[size]
    new Random().nextBytes(bytes)
    def buffer = ByteBuffer.wrap(bytes)
    return buffer
  }
}
