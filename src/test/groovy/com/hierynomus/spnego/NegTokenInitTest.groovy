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
package com.hierynomus.spnego

import com.hierynomus.ntlm.messages.NtlmNegotiate
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.protocol.commons.buffer.Buffer
import com.hierynomus.protocol.commons.buffer.Endian
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.microsoft.MicrosoftObjectIdentifiers
import spock.lang.Specification

class NegTokenInitTest extends Specification {

    def "should correctly decode GSS-API negInitToken"() {
        given:
        def bytes = getClass().getClassLoader().getResourceAsStream("spnego/negTokenInit_resp").bytes
        def buffer = new Buffer.PlainBuffer(bytes, Endian.LE)

        when:
        def negTokenInit = new NegTokenInit().read(buffer)

        then:
        negTokenInit.supportedMechTypes.size() == 2
    }

    def "should correctly encode ntlm choice negInitToken"() {
        given:
        def initToken = new NegTokenInit()
        def ntlmBuffer = new Buffer.PlainBuffer(Endian.LE)
        def spnegoBuffer = new Buffer.PlainBuffer(Endian.LE)

        when:
        new NtlmNegotiate().write(ntlmBuffer)
        initToken.addSupportedMech(MicrosoftObjectIdentifiers.microsoft.branch("2.2.10"))
        initToken.setMechToken(ntlmBuffer.compactData)
        initToken.write(spnegoBuffer)

        then:
        spnegoBuffer.compactData == getClass().getClassLoader().getResourceAsStream("spnego/negTokenInit_ntlm").bytes
    }
}
