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
package com.hierynomus.spnego;

import com.hierynomus.protocol.commons.buffer.Buffer;
import org.bouncycastle.asn1.*;

import java.io.IOException;

import static com.hierynomus.spnego.ObjectIdentifiers.SPNEGO;

abstract class NegToken {
    private int tokenTagNo;
    private String tokenName;

    public NegToken(int tokenTagNo, String tokenName) {
        this.tokenTagNo = tokenTagNo;
        this.tokenName = tokenName;
    }

    protected void writeGss(Buffer<?> buffer, ASN1EncodableVector negToken) throws IOException {
        DERTaggedObject negotiationToken = new DERTaggedObject(true, tokenTagNo, new DERSequence(negToken));

        ASN1EncodableVector implicitSeqGssApi = new ASN1EncodableVector();
        implicitSeqGssApi.add(SPNEGO);
        implicitSeqGssApi.add(negotiationToken);

        ASN1ApplicationSpecific gssApiHeader = new DERApplicationSpecific(0x0, implicitSeqGssApi);
        buffer.putRawBytes(gssApiHeader.getEncoded());
    }

    protected void parse(Buffer<?> buffer) throws IOException {
        ASN1Primitive applicationSpecific = new ASN1InputStream(buffer.asInputStream()).readObject();
        if (!(applicationSpecific instanceof ASN1ApplicationSpecific)) {
            throw new SpnegoException("Incorrect GSS-API ASN.1 token received, expected to find an [APPLICATION 0], not: " + applicationSpecific);
        }

        ASN1Sequence implicitSequence = (ASN1Sequence) ((ASN1ApplicationSpecific) applicationSpecific).getObject(BERTags.SEQUENCE);
        ASN1Encodable spnegoOid = implicitSequence.getObjectAt(0);
        if (!(spnegoOid instanceof ASN1ObjectIdentifier)) {
            throw new SpnegoException("Expected to find the SPNEGO OID (" + SPNEGO + "), not: " + spnegoOid);
        }

        ASN1Encodable negotiationToken = implicitSequence.getObjectAt(1);
        if (!(negotiationToken instanceof ASN1TaggedObject) || ((ASN1TaggedObject) negotiationToken).getTagNo() != tokenTagNo) {
            throw new SpnegoException("Expected to find the " + tokenName + " (CHOICE [" + tokenTagNo + "]) header, not: " + negotiationToken);
        }

        ASN1Primitive negToken = ((ASN1TaggedObject) negotiationToken).getObject();
        if (!(negToken instanceof ASN1Sequence)) {
            throw new SpnegoException("Expected a " + tokenName + " (SEQUENCE), not: " + negToken);
        }

        for (ASN1Encodable asn1Encodable : ((ASN1Sequence) negToken)) {
            if (!(asn1Encodable instanceof ASN1TaggedObject)) {
                throw new SpnegoException("Expected an ASN.1 TaggedObject as " + tokenName + " contents, not: " + asn1Encodable);
            }
            ASN1TaggedObject asn1TaggedObject = (ASN1TaggedObject) asn1Encodable;
            parseTagged(asn1TaggedObject);
        }
    }

    protected abstract void parseTagged(ASN1TaggedObject asn1TaggedObject) throws SpnegoException;

}
