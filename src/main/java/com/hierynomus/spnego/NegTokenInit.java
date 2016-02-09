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
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.smbj.common.SMBRuntimeException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * This class can encode and decode the SPNEGO negTokenInit Token.
 *
 * The entire token is an ASN.1 DER encoded sequence of bytes in little endian byte encoding.
 *
 * GSS-API      ::= [APPLICATION 0] IMPLICIT SEQUENCE {
 *     mech             MechType,
 *     negTokenInit     NegotiationToken
 * }
 *
 * NegotiationToken ::= CHOICE {
 *     negTokenInit [0] NegTokenInit,
 *     negTokenTarg [1] NegTokenTarg
 * }
 *
 * In the context of this class only the <em>NegTokenInit</em> is covered.
 *
 * The "mech" field of the GSS-API header is always set to the SPNEGO OID (1.3.6.1.5.5.2)
 *
 * NegTokenInit ::= SEQUENCE {
 *   mechTypes     [0]  MechTypeList  OPTIONAL,
 *   reqFlags      [1]  ContextFlags  OPTIONAL,
 *   mechToken     [2]  OCTET STRING  OPTIONAL,
 *   mechListMIC   [3]  OCTET STRING  OPTIONAL
 * }
 *
 * The negTokenInit will have a lead byte of <code>0xa0</code> (the choice tagged object).
 *
 * MechTypeList ::= SEQUENCE of MechType
 *
 * ContextFlags ::= BIT_STRING {
 *   delegFlag     (0),
 *   mutualFlag    (1),
 *   replayFlag    (2),
 *   sequenceFlag  (3),
 *   anonFlag      (4),
 *   confFlag      (5),
 *   integFlag     (6)
 * }
 *
 * MechType     ::= OBJECT IDENTIFIER
 */
public class NegTokenInit {
    private static final ASN1ObjectIdentifier SPNEGO_OID = IANAObjectIdentifiers.security_mechanisms.branch("2");

    private List<ASN1ObjectIdentifier> mechTypes = new ArrayList<>();
    private byte[] mechToken;

    public NegTokenInit() {
    }

    public void write(Buffer<?> buffer) {
        try {
            ASN1EncodableVector negTokenInit = new ASN1EncodableVector();
            addMechTypeList(negTokenInit);
            addMechToken(negTokenInit);

            DERTaggedObject negotiationToken = new DERTaggedObject(true, 0x0, new DERSequence(negTokenInit));

            ASN1EncodableVector implicitSeqGssApi = new ASN1EncodableVector();
            implicitSeqGssApi.add(SPNEGO_OID);
            implicitSeqGssApi.add(negotiationToken);

            ASN1ApplicationSpecific gssApiHeader = new DERApplicationSpecific(0x0, implicitSeqGssApi);
            buffer.putRawBytes(gssApiHeader.getEncoded());
        } catch (IOException e) {
            throw new SMBRuntimeException(e);
        }
    }

    public NegTokenInit read(byte[] bytes) throws IOException {
        return read(new Buffer.PlainBuffer(bytes, Endian.LE));
    }

    public NegTokenInit read(Buffer<?> buffer) throws IOException {
        try {
            ASN1Primitive applicationSpecific = new ASN1InputStream(buffer.asInputStream()).readObject();
            if (!(applicationSpecific instanceof ASN1ApplicationSpecific)) {
                throw new SpnegoException("Incorrect GSS-API ASN.1 token received, expected to find an [APPLICATION 0], not: " + applicationSpecific);
            }

            ASN1Sequence implicitSequence = (ASN1Sequence) ((ASN1ApplicationSpecific) applicationSpecific).getObject(BERTags.SEQUENCE);
            ASN1Encodable spnegoOid = implicitSequence.getObjectAt(0);
            if (!(spnegoOid instanceof ASN1ObjectIdentifier)) {
                throw new SpnegoException("Expected to find the SPNEGO OID (" + SPNEGO_OID + "), not: " + spnegoOid);
            }

            ASN1Encodable negotiationToken = implicitSequence.getObjectAt(1);
            if (!(negotiationToken instanceof ASN1TaggedObject) || ((ASN1TaggedObject) negotiationToken).getTagNo() != 0) {
                throw new SpnegoException("Expected to find the NegTokenInit (CHOICE [0]) header, not: " + negotiationToken);
            }

            ASN1Primitive negTokenInit = ((ASN1TaggedObject) negotiationToken).getObject();
            if (!(negTokenInit instanceof ASN1Sequence)) {
                throw new SpnegoException("Expected a NegTokenInit (SEQUENCE), not: " + negTokenInit);
            }

            for (ASN1Encodable asn1Encodable : ((ASN1Sequence) negTokenInit)) {
                if (!(asn1Encodable instanceof ASN1TaggedObject)) {
                    throw new SpnegoException("Expected an ASN.1 TaggedObject as NegTokenInit contents, not: " + asn1Encodable);
                }
                ASN1TaggedObject asn1TaggedObject = (ASN1TaggedObject) asn1Encodable;
                switch (asn1TaggedObject.getTagNo()) {
                    case 0:
                        readMechTypeList(asn1TaggedObject.getObject());
                        break;
                    case 2:
                        readMechToken(asn1TaggedObject.getObject());
                        break;
                    default:
                        throw new SpnegoException("Unknown Object Tag " + asn1TaggedObject.getTagNo() + " encountered.");
                }
            }

        } catch (SpnegoException e) {
            throw new SMBRuntimeException(e);
        }
        return this;
    }

    private void readMechToken(ASN1Primitive mechToken) throws SpnegoException {
        if (!(mechToken instanceof ASN1OctetString)) {
            throw new SpnegoException("Expected the MechToken (OCTET_STRING) contents, not: " + mechToken);
        }
        this.mechToken = ((ASN1OctetString) mechToken).getOctets();
    }

    private void readMechTypeList(ASN1Primitive sequence) throws SpnegoException {
        if (!(sequence instanceof ASN1Sequence)) {
            throw new SpnegoException("Expected the MechTypeList (SEQUENCE) contents, not: " + sequence);
        }
        for (ASN1Encodable mechType : (ASN1Sequence) sequence) {
            if (!(mechType instanceof ASN1ObjectIdentifier)) {
                throw new SpnegoException("Expected a MechType (OBJECT IDENTIFIER) as contents of the MechTypeList, not: " + mechType);
            }
            mechTypes.add((ASN1ObjectIdentifier) mechType);
        }
    }

    private void addMechToken(ASN1EncodableVector negTokenInit) {
        if (mechToken != null && mechToken.length > 0) {
            ASN1Primitive token = new DERTaggedObject(true, 0x02, new DEROctetString(mechToken));
            negTokenInit.add(token);
        }
    }

    private void addMechTypeList(ASN1EncodableVector negTokenInit) {
        if (mechTypes.size() > 0) {
            ASN1EncodableVector supportedMechVector = new ASN1EncodableVector();
            for (ASN1ObjectIdentifier mechType : mechTypes) {
                supportedMechVector.add(mechType);
            }

            ASN1Primitive asn1Encodables1 = new DERTaggedObject(true, 0x0, new DERSequence(supportedMechVector));
            negTokenInit.add(asn1Encodables1);
        }
    }

    public void addSupportedMech(ASN1ObjectIdentifier oid) {
        this.mechTypes.add(oid);
    }

    public void setMechToken(byte[] mechToken) {
        this.mechToken = mechToken;
    }

    public List<ASN1ObjectIdentifier> getSupportedMechTypes() {
        return mechTypes;
    }
}
