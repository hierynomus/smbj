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
package com.hierynomus.msdtyp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class SIDTest {
    @Test
    public void shouldHaveCorrectEveryoneSID() {
        assertEquals("S-1-1-0", SID.EVERYONE.toString());
    }

    public static Stream<Arguments> testSids() {
        return Stream.of(Arguments.of(SID.EVERYONE, "S-1-1-0"),
            Arguments.of(new SID((byte) 1, new byte[]{0, 0, 0, 0, 0, 5}, new long[]{21, 1234, 5678, 1357, 500}), "S-1-5-21-1234-5678-1357-500"),
            Arguments.of(new SID((byte) 1, new byte[]{0x36, (byte) 0xef, (byte) 0xab, (byte) 0xcd, 0x01, 0x23}, new long[]{21, 1234, 5678, 1357, 500}), "S-1-0x36efabcd0123-21-1234-5678-1357-500")
        );
    }

    @ParameterizedTest(name = "should parse SID {1}")
    @MethodSource("testSids")
    public void shouldParseSIDs(SID expectedSid, String sidString) {
        assertEquals(expectedSid, SID.fromString(sidString));
    }

    @Test
    public void shouldHaveSIDIdentity() {
        SID s1 = new SID((byte) 1, new byte[]{0, 0, 0, 0, 0, 1}, new long[]{0});
        SID s2 = new SID((byte) 1, new byte[]{0, 0, 0, 0, 0, 1}, new long[]{0});

        assertEquals(s1, s2);
        assertEquals(s1.hashCode(), s2.hashCode());
    }
}
