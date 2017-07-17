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
package com.hierynomus.protocol.commons.buffer

import spock.lang.Specification
import spock.lang.Unroll

import java.nio.charset.Charset

@Unroll
class BufferTest extends Specification {

  def "should read and write value #value as uint#size in #endian"() {
    given:
    def buffer = new Buffer.PlainBuffer(endian)

    when:
    buffer.metaClass.invokeMethod(buffer, "putUInt$size", value)

    then:
    buffer.printHex() == contents
    buffer.metaClass.invokeMethod(buffer, "readUInt$size") == value

    where:
    endian    | size | value               | contents
    Endian.LE | 16   | 255                 | "ff 00"
    Endian.LE | 16   | 256                 | "00 01"
    Endian.LE | 16   | 65535               | "ff ff"
    Endian.BE | 16   | 255                 | "00 ff"
    Endian.BE | 16   | 256                 | "01 00"
    Endian.BE | 16   | 65535               | "ff ff"
    Endian.LE | 24   | 255                 | "ff 00 00"
    Endian.LE | 24   | 0xff00ef            | "ef 00 ff"
    Endian.LE | 24   | 0xff0100            | "00 01 ff"
    Endian.LE | 24   | 0xffffff            | "ff ff ff"
    Endian.BE | 24   | 255                 | "00 00 ff"
    Endian.BE | 24   | 0xff00ef            | "ff 00 ef"
    Endian.BE | 24   | 0xff0100            | "ff 01 00"
    Endian.BE | 24   | 0xffffff            | "ff ff ff"
    Endian.LE | 32   | 255                 | "ff 00 00 00"
    Endian.LE | 32   | 0xffaa00            | "00 aa ff 00"
    Endian.LE | 32   | 0xffaa0011          | "11 00 aa ff"
    Endian.LE | 32   | 0xffffffffL         | "ff ff ff ff"
    Endian.BE | 32   | 255                 | "00 00 00 ff"
    Endian.BE | 32   | 0xffaa00            | "00 ff aa 00"
    Endian.BE | 32   | 0xffaa0011          | "ff aa 00 11"
    Endian.BE | 32   | 0xffffffffL         | "ff ff ff ff"
    Endian.LE | 64   | 255                 | "ff 00 00 00 00 00 00 00"
    Endian.LE | 64   | 0x66ff0066ff000000L | "00 00 00 ff 66 00 ff 66"
    Endian.LE | 64   | 0x7fffffffffffffffL | "ff ff ff ff ff ff ff 7f"
    Endian.BE | 64   | 255                 | "00 00 00 00 00 00 00 ff"
    Endian.BE | 64   | 0x66ff0066ff000000L | "66 ff 00 66 ff 00 00 00"
    Endian.BE | 64   | 0x7fffffffffffffffL | "7f ff ff ff ff ff ff ff"
  }

  def "should throw exception for #value as uint#size in #endian as it is out of range"() {
    given:
    def buffer = new Buffer.PlainBuffer(endian)

    when:
    buffer.metaClass.invokeMethod(buffer, "putUInt$size", value)

    then:
    def ex = thrown(RuntimeException)
    ex.message == "Invalid uint$size value: " + value

    where:
    endian    | size | value
    Endian.LE | 16   | 65536
    Endian.LE | 16   | -1
    Endian.BE | 16   | 65536
    Endian.BE | 16   | -1
    Endian.LE | 24   | 0x01000000
    Endian.LE | 24   | -1
    Endian.BE | 24   | 0x01000000
    Endian.BE | 24   | -1
    Endian.LE | 32   | 0x0100000000
    Endian.LE | 32   | -1
    Endian.BE | 32   | 0x0100000000
    Endian.BE | 32   | -1
    Endian.LE | 64   | 0x8000000000000000L
    Endian.LE | 64   | -1
    Endian.BE | 64   | 0x8000000000000000L
    Endian.BE | 64   | -1
  }

  def "should throw exception when trying to read too large uint64 value in #endian"() {
    given:
    def buffer = new Buffer.PlainBuffer(endian)
    buffer.putUInt32(val1)
    buffer.putUInt32(val2)

    when:
    buffer.readUInt64()

    then:
    def ex = thrown(Buffer.BufferException)
    ex.message == "Cannot handle values > " + Long.MAX_VALUE
    where:
    endian    | val1       | val2
    Endian.LE | 0x0        | 0x80000000L
    Endian.BE | 0x80000000 | 0x0
  }

  def "should read and write string '#value' as #unicode in #endian"() {
    given:
    def buffer = new Buffer.PlainBuffer(endian)
    def charset = Charset.forName(unicode)

    when:
    buffer.putString(value, charset)

    then:
    buffer.printHex() == contents
    buffer.readString(charset, value.length()) == value

    where:
    endian    | unicode    | value   | contents
    Endian.BE | "UTF-8"    | "abcde" | "61 62 63 64 65"
    Endian.BE | "UTF-16"   | "ab会意字" | "00 61 00 62 4f 1a 61 0f 5b 57"
    Endian.BE | "UTF-16LE" | "ab会意字" | "61 00 62 00 1a 4f 0f 61 57 5b"
    Endian.BE | "UTF-16BE" | "ab会意字" | "00 61 00 62 4f 1a 61 0f 5b 57"
    Endian.LE | "UTF-8"    | "abcde" | "61 62 63 64 65"
    Endian.LE | "UTF-16"   | "ab会意字" | "61 00 62 00 1a 4f 0f 61 57 5b"
    Endian.LE | "UTF-16LE" | "ab会意字" | "61 00 62 00 1a 4f 0f 61 57 5b"
    Endian.LE | "UTF-16BE" | "ab会意字" | "00 61 00 62 4f 1a 61 0f 5b 57"
  }

  def "should read a unsigned byte correctly through the inputstream"() {
    given:
    def buffer = new Buffer.PlainBuffer([100, 150] as byte[], Endian.LE)

    when:
    InputStream is = buffer.asInputStream()

    then:
    is.read() == 100
    is.read() == 150
  }
}
