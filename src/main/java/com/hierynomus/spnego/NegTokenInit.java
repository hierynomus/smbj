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

import com.hierynomus.asn1.ASN1InputStream;
import com.hierynomus.asn1.encodingrules.der.DERDecoder;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;
import com.hierynomus.asn1.types.ASN1TagClass;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject;
import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import com.hierynomus.asn1.types.string.ASN1OctetString;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;

import java.io.IOException;
import java.util.ArrayList;
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
    static final String ADS_IGNORE_PRINCIPAL = "not_defined_in_RFC4178@please_ignore";

    private List<ASN1ObjectIdentifier> mechTypes = new ArrayList<>();
    protected byte[] mechToken;

    public NegTokenInit() {
        super(0x0, "NegTokenInit");
    }

    public void write(Buffer<?> buffer) throws SpnegoException {
        try {
            List<ASN1Object> negTokenInit = new ArrayList<>();
//            ASN1EncodableVector negTokenInit = new ASN1EncodableVector();
            addMechTypeList(negTokenInit);
            addMechToken(negTokenInit);

            writeGss(buffer, new ASN1Sequence(negTokenInit));
        } catch (IOException e) {
            throw new SpnegoException("Unable to write NegTokenInit", e);
        }
    }

    public NegTokenInit read(byte[] bytes) throws SpnegoException {
        return read(new Buffer.PlainBuffer(bytes, Endian.LE));
    }

    private NegTokenInit read(Buffer<?> buffer) throws SpnegoException {
        try (ASN1InputStream is = new ASN1InputStream(new DERDecoder(), buffer.asInputStream())) {
            ASN1TaggedObject applicationSpecific = is.readObject();
            if (applicationSpecific.getTag().getAsn1TagClass() != ASN1TagClass.APPLICATION) {
                throw new SpnegoException("Incorrect GSS-API ASN.1 token received, expected to find an [APPLICATION 0], not: " + applicationSpecific);
            }
            ASN1Sequence implicitSequence = applicationSpecific.getObject(ASN1Tag.SEQUENCE);
            ASN1Object spnegoOid = implicitSequence.get(0);
            if (!(spnegoOid instanceof ASN1ObjectIdentifier)) {
                throw new SpnegoException("Expected to find the SPNEGO OID (" + SPNEGO + "), not: " + spnegoOid);
            }

            parseSpnegoToken(implicitSequence.get(1));
        } catch (IOException ioe) {
            throw new SpnegoException("Could not read NegTokenInit from buffer", ioe);
        }
        return this;
    }

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
            case 1:
                // Ignore reqFlags for now...
                break;
            case 2:
                readMechToken(asn1TaggedObject.getObject());
                break;
            case 3:
                // Ignore mechListMIC for now...
                break;
            default:
                throw new SpnegoException("Unknown Object Tag " + asn1TaggedObject.getTagNo() + " encountered.");
        }
    }

    void readMechToken(ASN1Object mechToken) throws SpnegoException {
        if (!(mechToken instanceof ASN1OctetString)) {
            throw new SpnegoException("Expected the MechToken (OCTET_STRING) contents, not: " + mechToken);
        }
        this.mechToken = ((ASN1OctetString) mechToken).getValue();
    }

    void readMechTypeList(ASN1Object sequence) throws SpnegoException {
        if (!(sequence instanceof ASN1Sequence)) {
            throw new SpnegoException("Expected the MechTypeList (SEQUENCE) contents, not: " + sequence);
        }
        for (ASN1Object mechType : (ASN1Sequence) sequence) {
            if (!(mechType instanceof ASN1ObjectIdentifier)) {
                throw new SpnegoException("Expected a MechType (OBJECT IDENTIFIER) as contents of the MechTypeList, not: " + mechType);
            }
            mechTypes.add((ASN1ObjectIdentifier) mechType);
        }
    }

    private void addMechToken(List<ASN1Object> negTokenInit) {
        if (mechToken != null && mechToken.length > 0) {
            ASN1TaggedObject token = new ASN1TaggedObject(ASN1Tag.contextSpecific(2).constructed(), new ASN1OctetString(mechToken), true);
            negTokenInit.add(token);
        }
    }

    private void addMechTypeList(List<ASN1Object> negTokenInit) {
        if (mechTypes.size() > 0) {
            List<ASN1Object> supportedMechVector = new ArrayList<ASN1Object>(mechTypes);
            negTokenInit.add(new ASN1TaggedObject(ASN1Tag.contextSpecific(0).constructed(), new ASN1Sequence(supportedMechVector), true));
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
