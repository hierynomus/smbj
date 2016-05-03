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
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.smbj.common.SMBRuntimeException;
import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import static com.hierynomus.spnego.ObjectIdentifiers.SPNEGO;

/**
 * This class can encode and decode the SPNEGO negTokenInit Token.
 * <p/>
 * The entire token is an ASN.1 DER encoded sequence of bytes in little endian byte encoding.
 * <p/>
 * The following is the full ASN.1 specification of the token:
 * <p/>
 * <pre>
 * GSSAPI          ::=  [APPLICATION 0] IMPLICIT SEQUENCE {
 *   mech                MechType,
 *   negTokenInit        NegotiationToken
 * }
 *
 * NegotiationToken ::=  CHOICE {
 *   negTokenInit   [0]  NegTokenInit,
 *   negTokenTarg   [1]  NegTokenTarg
 * }
 *
 * NegTokenInit     ::=  SEQUENCE {
 *   mechTypes      [0]  MechTypeList  OPTIONAL,
 *   reqFlags       [1]  ContextFlags  OPTIONAL,
 *   mechToken      [2]  OCTET STRING  OPTIONAL,
 *   mechListMIC    [3]  OCTET STRING  OPTIONAL
 * }
 *
 * MechTypeList     ::=  SEQUENCE of MechType
 *
 * ContextFlags     ::=  BIT_STRING {
 *   delegFlag      (0),
 *   mutualFlag     (1),
 *   replayFlag     (2),
 *   sequenceFlag   (3),
 *   anonFlag       (4),
 *   confFlag       (5),
 *   integFlag      (6)
 * }
 *
 * MechType         ::=  OBJECT IDENTIFIER
 * </pre>
 * <p/>
 * In the context of this class only the <em>NegTokenInit</em> is covered.
 * <p/>
 * <ul>
 * <li>When an InitToken is sent, it is prepended by the generic GSSAPI header.</li>
 * <li>The "mech" field of the GSSAPI header is always set to the SPNEGO OID (1.3.6.1.5.5.2)</li>
 * <li>The negTokenInit will have a lead byte of <code>0xa0</code> (the CHOICE tagged object).</li>
 * </ul>
 */
public class NegTokenInit extends SpnegoToken {

    private List<ASN1ObjectIdentifier> mechTypes = new ArrayList<>();
    private byte[] mechToken;

    public NegTokenInit() {
        super(0x0, "NegTokenInit");
    }

    public void write(Buffer<?> buffer) {
        try {
            ASN1EncodableVector negTokenInit = new ASN1EncodableVector();
            addMechTypeList(negTokenInit);
            addMechToken(negTokenInit);

            writeGss(buffer, negTokenInit);
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
            if (!(applicationSpecific instanceof BERApplicationSpecific || applicationSpecific instanceof DERApplicationSpecific)) {
                throw new SpnegoException("Incorrect GSS-API ASN.1 token received, expected to find an [APPLICATION 0], not: " + applicationSpecific);
            }
            ASN1Sequence implicitSequence = null;
            if (applicationSpecific instanceof BERApplicationSpecific) {
                implicitSequence = (ASN1Sequence) ((BERApplicationSpecific) applicationSpecific).getObject(BERTags.SEQUENCE);
            } else if (applicationSpecific instanceof DERApplicationSpecific) {
                implicitSequence = (ASN1Sequence) ((DERApplicationSpecific) applicationSpecific).getObject(BERTags.SEQUENCE);
            } else {
                throw new SpnegoException("Incorrect GSS-API ASN.1 token received, expected to find an [APPLICATION 0], not: " + applicationSpecific);
            }

            ASN1Encodable spnegoOid = implicitSequence.getObjectAt(0);
            if (!(spnegoOid instanceof ASN1ObjectIdentifier)) {
                throw new SpnegoException("Expected to find the SPNEGO OID (" + SPNEGO + "), not: " + spnegoOid);
            }

            parseSpnegoToken(implicitSequence.getObjectAt(1));
        } catch (SpnegoException e) {
            throw new SMBRuntimeException(e);
        }
        return this;
    }

    static final String ADS_IGNORE_PRINCIPAL = "not_defined_in_RFC4178@please_ignore";

    @Override
    protected void parseTagged(ASN1TaggedObject asn1TaggedObject) throws SpnegoException {
        if (asn1TaggedObject.getObject().toString().contains(ADS_IGNORE_PRINCIPAL)) {
            // Ignore
            return;
        }
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
        Enumeration mechTypeElems = ((ASN1Sequence) sequence).getObjects();
        while (mechTypeElems.hasMoreElements()) {
            ASN1Encodable mechType = (ASN1Encodable) mechTypeElems.nextElement();
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
