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
import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.math.BigInteger;

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
    protected void writeGss(Buffer<?> buffer, ASN1EncodableVector negToken) throws IOException {
        DERTaggedObject negotiationToken = new DERTaggedObject(true, 0x01, new DERSequence(negToken));

        buffer.putRawBytes(negotiationToken.getEncoded());
    }

    public void write(Buffer<?> buffer) throws SpnegoException {
        try {
            ASN1EncodableVector negTokenTarg = new ASN1EncodableVector();
            if (negotiationResult != null) {
                negTokenTarg.add(new DERTaggedObject(0x0, new ASN1Enumerated(negotiationResult)));
            }
            if (supportedMech != null) {
                negTokenTarg.add(new DERTaggedObject(0x01, supportedMech));
            }
            if (responseToken != null && responseToken.length > 0) {
                negTokenTarg.add(new DERTaggedObject(0x02, new DEROctetString(responseToken)));
            }
            if (mechListMic != null && mechListMic.length > 0) {
                negTokenTarg.add(new DERTaggedObject(0x03, new DEROctetString(mechListMic)));
            }

            writeGss(buffer, negTokenTarg);
        } catch (IOException e) {
            throw new SpnegoException("Could not write NegTokenTarg to buffer", e);
        }
    }


    public NegTokenTarg read(byte[] bytes) throws SpnegoException {
        return read(new Buffer.PlainBuffer(bytes, Endian.LE));
    }

    private NegTokenTarg read(Buffer<?> buffer) throws SpnegoException {
        try (ASN1InputStream is = new ASN1InputStream(buffer.asInputStream())) {
            ASN1Primitive instance = is.readObject();
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

    private void readResponseToken(ASN1Primitive responseToken) throws SpnegoException {
        if (!(responseToken instanceof ASN1OctetString)) {
            throw new SpnegoException("Expected the responseToken (OCTET_STRING) contents, not: " + responseToken);
        }
        this.responseToken = ((ASN1OctetString) responseToken).getOctets();

    }

    private void readMechListMIC(ASN1Primitive mic) throws SpnegoException {
        if (!(mic instanceof ASN1OctetString)) {
            throw new SpnegoException("Expected the responseToken (OCTET_STRING) contents, not: " + mic);
        }
        this.mechListMic = ((ASN1OctetString) mic).getOctets();

    }

    private void readSupportedMech(ASN1Primitive supportedMech) throws SpnegoException {
        if (!(supportedMech instanceof ASN1ObjectIdentifier)) {
            throw new SpnegoException("Expected the supportedMech (OBJECT IDENTIFIER) contents, not: " + supportedMech);
        }
        this.supportedMech = (ASN1ObjectIdentifier) supportedMech;

    }

    private void readNegResult(ASN1Primitive object) throws SpnegoException {
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
