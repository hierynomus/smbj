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

import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.encodingrules.der.DEREncoder;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject;
import com.hierynomus.protocol.commons.buffer.Buffer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static com.hierynomus.spnego.ObjectIdentifiers.SPNEGO;

abstract class SpnegoToken {

    private int tokenTagNo;
    private String tokenName;

    public SpnegoToken(int tokenTagNo, String tokenName) {
        this.tokenTagNo = tokenTagNo;
        this.tokenName = tokenName;
    }

    protected void writeGss(Buffer<?> buffer, ASN1Object negToken) throws IOException {
        ASN1TaggedObject negotiationToken = new ASN1TaggedObject(ASN1Tag.contextSpecific(tokenTagNo).constructed(), negToken);

        List<ASN1Object> implicitSeqGssApi = new ArrayList<>();
        implicitSeqGssApi.add(SPNEGO);
        implicitSeqGssApi.add(negotiationToken);

        ASN1TaggedObject token = new ASN1TaggedObject(ASN1Tag.application(0), new ASN1Sequence(implicitSeqGssApi), false);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ASN1OutputStream out = new ASN1OutputStream(new DEREncoder(), baos)) {
            out.writeObject(token);
        }
        buffer.putRawBytes(baos.toByteArray());
    }

    protected void parseSpnegoToken(ASN1Object spnegoToken) throws SpnegoException {
        if (!(spnegoToken instanceof ASN1TaggedObject) || ((ASN1TaggedObject) spnegoToken).getTagNo() != tokenTagNo) {
            throw new SpnegoException("Expected to find the " + tokenName + " (CHOICE [" + tokenTagNo + "]) header, not: " + spnegoToken);
        }

        ASN1Object negToken = ((ASN1TaggedObject) spnegoToken).getObject();
        if (!(negToken instanceof ASN1Sequence)) {
            throw new SpnegoException("Expected a " + tokenName + " (SEQUENCE), not: " + negToken);
        }

        for (ASN1Object asn1Object : (ASN1Sequence) negToken) {
            if (!(asn1Object instanceof ASN1TaggedObject)) {
                throw new SpnegoException("Expected an ASN.1 TaggedObject as " + tokenName + " contents, not: " + asn1Object);
            }
            ASN1TaggedObject asn1TaggedObject = (ASN1TaggedObject) asn1Object;
            parseTagged(asn1TaggedObject);
        }
    }

    protected abstract void parseTagged(ASN1TaggedObject asn1TaggedObject) throws SpnegoException;

}
