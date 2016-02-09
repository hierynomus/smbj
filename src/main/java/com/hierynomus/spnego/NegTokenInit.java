package com.hierynomus.spnego;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBRuntimeException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class NegTokenInit {
    private static final ASN1ObjectIdentifier SPNEGO_OID = IANAObjectIdentifiers.security_mechanisms.branch("2");

    private List<ASN1ObjectIdentifier> mechTypes = new ArrayList<>();
    private byte[] mechToken;

    public NegTokenInit() {
    }

    public void write(Buffer<?> buffer) {
        try {
            ASN1EncodableVector vector = new ASN1EncodableVector();
            vector.add(SPNEGO_OID);
            ASN1EncodableVector supportedMechVector = new ASN1EncodableVector();
            for (ASN1ObjectIdentifier mechType : mechTypes) {
                supportedMechVector.add(mechType);
            }

            ASN1Primitive asn1Encodables1 = new DERTaggedObject(true, 0x0, new DERSequence(supportedMechVector));
            ASN1Primitive token = new DERTaggedObject(true, 0x02, new DEROctetString(mechToken));
            ASN1EncodableVector asn1Encodables = new ASN1EncodableVector();
            asn1Encodables.add(asn1Encodables1);
            asn1Encodables.add(token);
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
