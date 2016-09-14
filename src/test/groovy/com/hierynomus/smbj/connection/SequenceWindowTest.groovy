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
package com.hierynomus.smbj.connection

import com.hierynomus.smbj.common.SMBRuntimeException
import spock.lang.Specification

class SequenceWindowTest extends Specification {
    SequenceWindow window

    def setup() {
        window = new SequenceWindow();
    }

    def "should start at 0"() {
        expect:
        window.get() == 0
    }

    def "should be depleted when not granted new tokens after get"() {
        when:
        window.get()

        then:
        window.available() == 0
    }

    def "should throw exception when calling get on depleted window"() {
        given:
        window.get()

        when:
        window.get()

        then:
        def ex = thrown(SMBRuntimeException)
        ex.getMessage() == "No more credits available to hand out sequence number"
    }

    def "should return array of sequence numbers for multi-credit request"() {
        given:
        window.creditsGranted(10)

        expect:
        window.get(10) == [0, 1, 2, 3, 4, 5, 6, 7, 8, 9] as long[]
    }

    def "should throw exception when requesting more sequence numbers than credits available"() {
        given:
        window.creditsGranted(2)

        when:
        window.get(4)

        then:
        def ex = thrown(SMBRuntimeException)
        ex.getMessage() == "Not enough credits (3 available) to hand out 4 sequence numbers"
    }

    def "should increment sequence number for consecutive calls"() {
        given:
        window.creditsGranted(2)

        expect:
        window.get() == 0
        window.get() == 1
    }

    def "when crediting disabled, there is an 'unlimited' supply of sequence tokens"() {
        given:
        window.disableCredits()

        expect:
        window.available() == Integer.MAX_VALUE
        window.get() == 0
        window.get() == 1
    }
}
