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

import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.types.*;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject;
import com.hierynomus.protocol.commons.buffer.Buffer;
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

//    protected void writeGss(Buffer<?> buffer, ASN1EncodableVector negToken) throws IOException {
//        DERTaggedObject negotiationToken = new DERTaggedObject(true, tokenTagNo, new DERSequence(negToken));
//
//        ASN1EncodableVector implicitSeqGssApi = new ASN1EncodableVector();
//        implicitSeqGssApi.add(SPNEGO);
//        implicitSeqGssApi.add(negotiationToken);
//
//        DERApplicationSpecific gssApiHeader = new DERApplicationSpecific(0x0, implicitSeqGssApi);
//        buffer.putRawBytes(gssApiHeader.getEncoded());
//    }

    protected void parseSpnegoToken(com.hierynomus.asn1.types.ASN1Object spnegoToken) throws IOException {
        if (!(spnegoToken instanceof ASN1TaggedObject) || spnegoToken.getTag().getTag() != tokenTagNo) {
            throw new SpnegoException("Expected to find the " + tokenName + " (CHOICE [" + tokenTagNo + "]) header, not: " + spnegoToken);
        }

        ASN1Sequence negToken = null;
        try {
            negToken = ((ASN1TaggedObject) spnegoToken).getObject(ASN1Tag.SEQUENCE);
        } catch (ASN1ParseException pe) {
            throw new SpnegoException("Expected a " + tokenName + " (SEQUENCE)", pe);
        }

        for (ASN1Object asn1Object : negToken) {
            if (!(asn1Object instanceof ASN1TaggedObject)) {
                throw new SpnegoException("Expected an ASN.1 TaggedObject as " + tokenName + " contents, not: " + asn1Object);
            }
            parseTagged((ASN1TaggedObject) asn1Object);
        }
    }

    protected abstract void parseTagged(ASN1TaggedObject asn1TaggedObject) throws SpnegoException;

}
