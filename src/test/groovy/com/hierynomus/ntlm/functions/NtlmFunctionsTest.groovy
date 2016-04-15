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
package com.hierynomus.ntlm.functions

import org.bouncycastle.jce.provider.BouncyCastleProvider
import spock.lang.Specification

import java.security.Security

class NtlmFunctionsTest extends Specification {

    def setup() {
        if (!Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
            Security.addProvider(new BouncyCastleProvider())
        }
    }

    def"should correctly determine LMOWFv1 LM hash"() {
        expect:
        NtlmFunctions.LMOWFv1("admin", null, null) == [0xf0, 0xd4, 0x12, 0xbd, 0x76, 0x4f, 0xfe, 0x81, 0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee] as byte[]
    }
}
