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
package com.hierynomus.mssmb2

import com.hierynomus.protocol.commons.ByteArrayUtils
import spock.lang.Specification

class LeaseKeySpec extends Specification {
    static final byte[] BYTES16 = ByteArrayUtils.parseHex("000102030405060708090a0b0c0d0e0f")

    def "rejects non-16-byte input"() {
        when:
        new LeaseKey(new byte[15])
        then:
        thrown(IllegalArgumentException)
    }

    def "equal keys are equals and share hashCode (usable as Map key)"() {
        given:
        def a = new LeaseKey(BYTES16)
        def b = new LeaseKey(ByteArrayUtils.parseHex("000102030405060708090a0b0c0d0e0f"))
        expect:
        a == b
        a.hashCode() == b.hashCode()
        [(a): "x"][b] == "x"
    }

    def "a differing byte makes keys unequal"() {
        given:
        def other = ByteArrayUtils.parseHex("990102030405060708090a0b0c0d0e0f")
        expect:
        new LeaseKey(BYTES16) != new LeaseKey(other)
    }

    def "getBytes returns a defensive copy"() {
        given:
        def key = new LeaseKey(BYTES16)
        when:
        def out = key.getBytes()
        out[0] = 0x77 as byte
        then:
        ByteArrayUtils.toHex(key.getBytes()) == "000102030405060708090a0b0c0d0e0f"
    }

    def "random yields 16 distinct bytes"() {
        expect:
        LeaseKey.random().getBytes().length == 16
        LeaseKey.random() != LeaseKey.random()
    }

    def "zero key isAllZero, a populated key is not"() {
        expect:
        LeaseKey.zero().isAllZero()
        !new LeaseKey(BYTES16).isAllZero()
    }
}
