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
import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.encodingrules.der.DERDecoder;
import com.hierynomus.asn1.encodingrules.der.DEREncoder;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject;
import com.hierynomus.asn1.types.primitive.ASN1Enumerated;
import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import com.hierynomus.asn1.types.string.ASN1OctetString;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * This class can encode and decode the SPNEGO negTokenInit Token.
 * <p/>
 * The entire token is an ASN.1 DER encoded sequence of bytes in little endian byte encoding.
 * <p/>
 * The following if the ASN.1 specification of the full structure of the token:
 * <p/>
 * <pre>
 * NegotiationToken ::=  CHOICE {
 *   negTokenInit   [0]  NegTokenInit,
 *   negTokenTarg   [1]  NegTokenTarg
 * }
 *
 * NegTokenTarg     ::=  SEQUENCE {
 *   negResult      [0]  ENUMERATED {
 *                            accept_completed (0),
 *                            accept_incomplete (1),
 *                            rejected (2) }  OPTIONAL,
 *   supportedMech  [1]  MechType             OPTIONAL,
 *   responseToken  [2]  OCTET STRING         OPTIONAL,
 *   mechListMIC    [3]  OCTET STRING         OPTIONAL
 * }
 *
 * MechType         ::=  OBJECT IDENTIFIER
 * </pre>
 * <p/>
 * In the context of this class only the <em>NegTokenTarg</em> is covered.
 */
public class NegTokenTarg extends SpnegoToken {

    private BigInteger negotiationResult;
    private ASN1ObjectIdentifier supportedMech;
    private byte[] responseToken;
    private byte[] mechListMic;

    public NegTokenTarg() {
        super(0x01, "NegTokenTarg");
    }

    // Override writeGss for NTLMSSP_AUTH since Samba does not like putting the OID for SPNEGO
    protected void writeGss(Buffer<?> buffer, ASN1Object negToken) throws IOException {
        ASN1TaggedObject negotiationToken = new ASN1TaggedObject(ASN1Tag.contextSpecific(0x01).constructed(), negToken, true);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ASN1OutputStream out = new ASN1OutputStream(new DEREncoder(), baos)) {
            out.writeObject(negotiationToken);
        }
        buffer.putRawBytes(baos.toByteArray());
    }

    public void write(Buffer<?> buffer) throws SpnegoException {
        List<ASN1Object> negTokenTarg = new ArrayList<>();
        try {
            if (negotiationResult != null) {
                negTokenTarg.add(new ASN1TaggedObject(ASN1Tag.contextSpecific(0x0).constructed(), new ASN1Enumerated(negotiationResult)));
            }
            if (supportedMech != null) {
                negTokenTarg.add(new ASN1TaggedObject(ASN1Tag.contextSpecific(0x01).constructed(), supportedMech));
            }
            if (responseToken != null && responseToken.length > 0) {
                negTokenTarg.add(new ASN1TaggedObject(ASN1Tag.contextSpecific(0x02).constructed(), new ASN1OctetString(responseToken)));
            }
            if (mechListMic != null && mechListMic.length > 0) {
                negTokenTarg.add(new ASN1TaggedObject(ASN1Tag.contextSpecific(0x03).constructed(), new ASN1OctetString(mechListMic)));
            }

            writeGss(buffer, new ASN1Sequence(negTokenTarg));
        } catch (IOException e) {
            throw new SpnegoException("Could not write NegTokenTarg to buffer", e);
        }
    }


    public NegTokenTarg read(byte[] bytes) throws SpnegoException {
        return read(new Buffer.PlainBuffer(bytes, Endian.LE));
    }

    private NegTokenTarg read(Buffer<?> buffer) throws SpnegoException {
        try (ASN1InputStream is = new ASN1InputStream(new DERDecoder(), buffer.asInputStream())) {
            ASN1Object instance = is.readObject();
            parseSpnegoToken(instance);
        } catch (IOException e) {
            throw new SpnegoException("Could not read NegTokenTarg from buffer", e);
        }
        return this;
    }

    @Override
    protected void parseTagged(ASN1TaggedObject asn1TaggedObject) throws SpnegoException {
        switch (asn1TaggedObject.getTagNo()) {
            case 0:
                readNegResult(asn1TaggedObject.getObject());
                break;
            case 1:
                readSupportedMech(asn1TaggedObject.getObject());
                break;
            case 2:
                readResponseToken(asn1TaggedObject.getObject());
                break;
            case 3:
                readMechListMIC(asn1TaggedObject.getObject());
                break;
            default:
                throw new SpnegoException("Unknown Object Tag " + asn1TaggedObject.getTagNo() + " encountered.");
        }

    }

    private void readResponseToken(ASN1Object responseToken) throws SpnegoException {
        if (!(responseToken instanceof ASN1OctetString)) {
            throw new SpnegoException("Expected the responseToken (OCTET_STRING) contents, not: " + responseToken);
        }
        this.responseToken = ((ASN1OctetString) responseToken).getValue();

    }

    private void readMechListMIC(ASN1Object mic) throws SpnegoException {
        if (!(mic instanceof ASN1OctetString)) {
            throw new SpnegoException("Expected the responseToken (OCTET_STRING) contents, not: " + mic);
        }
        this.mechListMic = ((ASN1OctetString) mic).getValue();

    }

    private void readSupportedMech(ASN1Object supportedMech) throws SpnegoException {
        if (!(supportedMech instanceof ASN1ObjectIdentifier)) {
            throw new SpnegoException("Expected the supportedMech (OBJECT IDENTIFIER) contents, not: " + supportedMech);
        }
        this.supportedMech = (ASN1ObjectIdentifier) supportedMech;

    }

    private void readNegResult(ASN1Object object) throws SpnegoException {
        if (!(object instanceof ASN1Enumerated)) {
            throw new SpnegoException("Expected the negResult (ENUMERATED) contents, not: " + supportedMech);
        }
        this.negotiationResult = ((ASN1Enumerated) object).getValue();
    }

    public BigInteger getNegotiationResult() {
        return negotiationResult;
    }

    public void setNegotiationResult(BigInteger negotiationResult) {
        this.negotiationResult = negotiationResult;
    }

    public ASN1ObjectIdentifier getSupportedMech() {
        return supportedMech;
    }

    public void setSupportedMech(ASN1ObjectIdentifier supportedMech) {
        this.supportedMech = supportedMech;
    }

    public byte[] getResponseToken() {
        return responseToken;
    }

    public void setResponseToken(byte[] responseToken) {
        this.responseToken = responseToken;
    }

    public byte[] getMechListMic() {
        return mechListMic;
    }

    public void setMechListMic(byte[] mechListMic) {
        this.mechListMic = mechListMic;
    }
}
