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

import com.hierynomus.asn1.types.constructed.ASN1TaggedObject;

/**
 * This class can encode and decode the MS extension of the SPNEGO negTokenInit2 Token.
 * <p/>
 * The NegTokenInit2 message extends the NegTokenInit message with a <pre>negHints</pre> field.
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
 *   negTokenInit   [0]  NegTokenInit2,
 *   negTokenTarg   [1]  NegTokenTarg
 * }
 *
 * NegTokenInit2    ::=  SEQUENCE {
 *   mechTypes      [0]  MechTypeList  OPTIONAL,
 *   reqFlags       [1]  ContextFlags  OPTIONAL,
 *   mechToken      [2]  OCTET STRING  OPTIONAL,
 *   negHints       [3]  NegHints OPTIONAL,
 *   mechListMIC    [4]  OCTET STRING  OPTIONAL
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
 * NegHints         ::=  SEQUENCE {
 *   hintName       [0] GeneralString OPTIONAL,
 *   hintAddress    [1] OCTET STRING OPTIONAL
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
public class NegTokenInit2 extends NegTokenInit {

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
                // Ignore negHints for now...
                break;
            case 4:
                // Ignore mechListMIC for now...
                break;
            default:
                throw new SpnegoException("Unknown Object Tag " + asn1TaggedObject.getTagNo() + " encountered.");
        }

    }
}
