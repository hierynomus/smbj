/*
 * Copyright (C)2016 - Jeroen van Erp <jeroen@hierynomus.com>
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
        endian              | size | value               | contents
        new Endian.Little() | 16   | 255                 | "ff 00"
        new Endian.Little() | 16   | 256                 | "00 01"
        new Endian.Little() | 16   | 65535               | "ff ff"
        new Endian.Big()    | 16   | 255                 | "00 ff"
        new Endian.Big()    | 16   | 256                 | "01 00"
        new Endian.Big()    | 16   | 65535               | "ff ff"
        new Endian.Little() | 24   | 255                 | "ff 00 00"
        new Endian.Little() | 24   | 0xff00ef            | "ef 00 ff"
        new Endian.Little() | 24   | 0xff0100            | "00 01 ff"
        new Endian.Little() | 24   | 0xffffff            | "ff ff ff"
        new Endian.Big()    | 24   | 255                 | "00 00 ff"
        new Endian.Big()    | 24   | 0xff00ef            | "ff 00 ef"
        new Endian.Big()    | 24   | 0xff0100            | "ff 01 00"
        new Endian.Big()    | 24   | 0xffffff            | "ff ff ff"
        new Endian.Little() | 32   | 255                 | "ff 00 00 00"
        new Endian.Little() | 32   | 0xffaa00            | "00 aa ff 00"
        new Endian.Little() | 32   | 0xffaa0011          | "11 00 aa ff"
        new Endian.Little() | 32   | 0xffffffffL         | "ff ff ff ff"
        new Endian.Big()    | 32   | 255                 | "00 00 00 ff"
        new Endian.Big()    | 32   | 0xffaa00            | "00 ff aa 00"
        new Endian.Big()    | 32   | 0xffaa0011          | "ff aa 00 11"
        new Endian.Big()    | 32   | 0xffffffffL         | "ff ff ff ff"
        new Endian.Little() | 64   | 255                 | "ff 00 00 00 00 00 00 00"
        new Endian.Little() | 64   | 0x66ff0066ff000000L | "00 00 00 ff 66 00 ff 66"
        new Endian.Little() | 64   | 0x7fffffffffffffffL | "ff ff ff ff ff ff ff 7f"
        new Endian.Big()    | 64   | 255                 | "00 00 00 00 00 00 00 ff"
        new Endian.Big()    | 64   | 0x66ff0066ff000000L | "66 ff 00 66 ff 00 00 00"
        new Endian.Big()    | 64   | 0x7fffffffffffffffL | "7f ff ff ff ff ff ff ff"
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
        endian              | size | value
        new Endian.Little() | 16   | 65536
        new Endian.Little() | 16   | -1
        new Endian.Big()    | 16   | 65536
        new Endian.Big()    | 16   | -1
        new Endian.Little() | 24   | 0x01000000
        new Endian.Little() | 24   | -1
        new Endian.Big()    | 24   | 0x01000000
        new Endian.Big()    | 24   | -1
        new Endian.Little() | 32   | 0x0100000000
        new Endian.Little() | 32   | -1
        new Endian.Big()    | 32   | 0x0100000000
        new Endian.Big()    | 32   | -1
        new Endian.Little() | 64   | 0x8000000000000000L
        new Endian.Little() | 64   | -1
        new Endian.Big()    | 64   | 0x8000000000000000L
        new Endian.Big()    | 64   | -1
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
        endian              | val1       | val2
        new Endian.Little() | 0x0        | 0x80000000L
        new Endian.Big()    | 0x80000000 | 0x0
    }
}
