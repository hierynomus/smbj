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
package com.hierynomus.spnego;

import com.hierynomus.protocol.commons.buffer.Buffer;
import org.bouncycastle.asn1.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Enumeration;

import static com.hierynomus.spnego.ObjectIdentifiers.SPNEGO;

abstract class SpnegoToken {
    private static final Logger logger = LoggerFactory.getLogger(SpnegoToken.class);

    private int tokenTagNo;
    private String tokenName;

    public SpnegoToken(int tokenTagNo, String tokenName) {
        this.tokenTagNo = tokenTagNo;
        this.tokenName = tokenName;
    }

    protected void writeGss(Buffer<?> buffer, ASN1EncodableVector negToken) throws IOException {
        DERTaggedObject negotiationToken = new DERTaggedObject(true, tokenTagNo, new DERSequence(negToken));

        ASN1EncodableVector implicitSeqGssApi = new ASN1EncodableVector();
        implicitSeqGssApi.add(SPNEGO);
        implicitSeqGssApi.add(negotiationToken);

        DERApplicationSpecific gssApiHeader = new DERApplicationSpecific(0x0, implicitSeqGssApi);
        buffer.putRawBytes(gssApiHeader.getEncoded());
    }

    protected void parseSpnegoToken(ASN1Encodable spnegoToken) throws IOException {
        if (!(spnegoToken instanceof ASN1TaggedObject) || ((ASN1TaggedObject) spnegoToken).getTagNo() != tokenTagNo) {
            throw new SpnegoException("Expected to find the " + tokenName + " (CHOICE [" + tokenTagNo + "]) header, not: " + spnegoToken);
        }

        ASN1Primitive negToken = ((ASN1TaggedObject) spnegoToken).getObject();
        if (!(negToken instanceof ASN1Sequence)) {
            throw new SpnegoException("Expected a " + tokenName + " (SEQUENCE), not: " + negToken);
        }

        Enumeration tokenObjects = ((ASN1Sequence) negToken).getObjects();
        while(tokenObjects.hasMoreElements()) {
            ASN1Encodable asn1Encodable = (ASN1Encodable)tokenObjects.nextElement();
            if (!(asn1Encodable instanceof ASN1TaggedObject)) {
                throw new SpnegoException("Expected an ASN.1 TaggedObject as " + tokenName + " contents, not: " + asn1Encodable);
            }
            ASN1TaggedObject asn1TaggedObject = (ASN1TaggedObject) asn1Encodable;
            parseTagged(asn1TaggedObject);
        }
    }

    protected abstract void parseTagged(ASN1TaggedObject asn1TaggedObject) throws SpnegoException;

}
