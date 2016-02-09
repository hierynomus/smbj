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

    def "should correctly encode ntlm choice InitToken"() {
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

    def "trying out tagged object"() {
        given:
        def ntlmBuffer = new Buffer.PlainBuffer(Endian.LE)

        when:
        new NtlmNegotiate().write(ntlmBuffer)
        def string = new DEROctetString(ntlmBuffer.compactData)
        def taggedObject = new DERTaggedObject(0x02, string)

        then:
        println(ByteArrayUtils.printHex(taggedObject.getEncoded()))
        true
    }
}
