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

class FileByteChunkProviderSpec extends Specification {

  def "should write 1 chunk to outputStream"() {
    given:
    def file = getFileWithRandomData(ByteChunkProvider.CHUNK_SIZE)
    def provider = new FileByteChunkProvider(file)
    def baos = new ByteArrayOutputStream()

    when:
    provider.prepareWrite(ByteChunkProvider.CHUNK_SIZE)
    provider.writeChunk(baos)

    then:
    baos.toByteArray() == file.bytes
    provider.offset == ByteChunkProvider.CHUNK_SIZE
  }

  def "should write part of chunk to outputStream"() {
    given:
    def file = getFileWithRandomData(1024)
    def provider = new FileByteChunkProvider(file)
    def baos = new ByteArrayOutputStream()

    when:
    provider.prepareWrite(ByteChunkProvider.CHUNK_SIZE)
    provider.writeChunk(baos)

    then:
    baos.toByteArray() == file.bytes
    provider.offset == 1024
    !provider.isAvailable()

    cleanup:
    file.delete()
  }

  def "should have available after writing first chunk"() {
    given:
    def file = getFileWithRandomData(ByteChunkProvider.CHUNK_SIZE + 1)
    def provider = new FileByteChunkProvider(file)
    def baos = new ByteArrayOutputStream()

    when:
    provider.prepareWrite(ByteChunkProvider.CHUNK_SIZE)
    provider.writeChunk(baos)

    then:
    provider.offset == ByteChunkProvider.CHUNK_SIZE
    provider.isAvailable()

    cleanup:
    file.delete()
  }

  def "should start at provided offset"() {
    given:
    def file = getFileWithRandomData(ByteChunkProvider.CHUNK_SIZE)
    def provider = new FileByteChunkProvider(file, 100)
    def baos = new ByteArrayOutputStream()

    when:
    provider.prepareWrite(ByteChunkProvider.CHUNK_SIZE)
    provider.writeChunk(baos)

    then:
    def tmpBytes = new byte[ByteChunkProvider.CHUNK_SIZE - 100]
    System.arraycopy(file.bytes, 100, tmpBytes, 0, tmpBytes.length)
    baos.toByteArray() == tmpBytes
    provider.offset == ByteChunkProvider.CHUNK_SIZE
    !provider.isAvailable()

    cleanup:
    file.delete()
  }

  private def getFileWithRandomData(int size) {
    def bytes = new byte[size]
    new Random().nextBytes(bytes)
    def file = File.createTempFile("foo", "txt")
    file.withOutputStream {
      it.write(bytes)
    }
    return file
  }
}
