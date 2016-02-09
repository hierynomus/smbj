package com.hierynomus.spnego;

import com.hierynomus.protocol.commons.buffer.Buffer;
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
            ASN1EncodableVector supportedMechVector = new ASN1EncodableVector();
            for (ASN1ObjectIdentifier mechType : mechTypes) {
                supportedMechVector.add(mechType);
            }

            ASN1Primitive asn1Encodables1 = new DERTaggedObject(true, 0x0, new DERSequence(supportedMechVector));
            ASN1Primitive token = new DERTaggedObject(true, 0x02, new DEROctetString(mechToken));
            ASN1EncodableVector asn1Encodables = new ASN1EncodableVector();
            asn1Encodables.add(asn1Encodables1);
            asn1Encodables.add(token);

            ASN1EncodableVector vector = new ASN1EncodableVector();
            vector.add(SPNEGO_OID);
            vector.add(new DERTaggedObject(true, 0x0, new DERSequence(asn1Encodables)));

            DERApplicationSpecific berApplicationSpecific = new DERApplicationSpecific(0x0, vector);
            buffer.putRawBytes(berApplicationSpecific.getEncoded());
        } catch (IOException e) {
            throw new SMBRuntimeException(e);
        }
    }

    public void addSupportedMech(ASN1ObjectIdentifier oid) {
        this.mechTypes.add(oid);
    }

    public void setMechToken(byte[] mechToken) {
        this.mechToken = mechToken;
    }
}
