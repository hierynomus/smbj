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
package com.hierynomus.smbj.auth;

import com.hierynomus.ntlm.messages.NtlmChallenge;
import com.hierynomus.ntlm.messages.NtlmNegotiate;
import com.hierynomus.ntlm.messages.NtlmPacket;
import com.hierynomus.protocol.commons.ByteArrayUtils;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.smb2.SMB2Packet;
import com.hierynomus.smbj.smb2.SMB2StatusCode;
import com.hierynomus.smbj.smb2.messages.SMB2SessionSetup;
import com.hierynomus.smbj.transport.TransportException;
import com.hierynomus.spnego.NegTokenInit;
import com.hierynomus.spnego.NegTokenTarg;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.microsoft.MicrosoftObjectIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;

public class NtlmAuthenticator implements Authenticator {
    private static final Logger logger = LoggerFactory.getLogger(NtlmAuthenticator.class);

    private static final ASN1ObjectIdentifier NTLMSSP = MicrosoftObjectIdentifiers.microsoft.branch("2.2.10");

    public static class Factory implements com.hierynomus.protocol.commons.Factory.Named<NtlmAuthenticator> {
        @Override
        public String getName() {
            // The OID for NTLMSSP
            return "1.3.6.1.4.1.311.2.2.10";
        }

        @Override
        public NtlmAuthenticator create() {
            return new NtlmAuthenticator();
        }
    }

    public long authenticate(Connection connection, String username, char[] password) throws TransportException {
        try {
            logger.info("Authenticating {} on {} using NTLM", username, connection.getRemoteHostname());
            SMB2SessionSetup smb2SessionSetup = new SMB2SessionSetup(connection.getNegotiatedDialect());
            NtlmNegotiate ntlmNegotiate = new NtlmNegotiate();
            byte[] asn1 = negTokenInit(ntlmNegotiate);
            smb2SessionSetup.setSecurityBuffer(asn1);
            connection.send(smb2SessionSetup);
            SMB2SessionSetup receive = (SMB2SessionSetup) connection.receive();
            if (receive.getHeader().getStatus() == SMB2StatusCode.STATUS_MORE_PROCESSING_REQUIRED) {
                logger.debug("More processing required for authentication of {}", username);
                byte[] securityBuffer = receive.getSecurityBuffer();
                logger.info("Received token: {}", ByteArrayUtils.printHex(securityBuffer));

                NegTokenTarg negTokenTarg = new NegTokenTarg().read(securityBuffer);
                BigInteger negotiationResult = negTokenTarg.getNegotiationResult();
                NtlmChallenge read = (NtlmChallenge) new NtlmChallenge().read(new Buffer.PlainBuffer(negTokenTarg.getResponseToken(), Endian.LE));
                logger.debug("Received NTLM challenge from: {}", read.getTargetName());
            }
            return 0;
        } catch (IOException | Buffer.BufferException e) {
            throw new TransportException(e);
        }
    }

    private byte[] negTokenInit(NtlmNegotiate ntlmNegotiate) {
        NegTokenInit negTokenInit = new NegTokenInit();
        negTokenInit.addSupportedMech(NTLMSSP);
        Buffer.PlainBuffer ntlmBuffer = new Buffer.PlainBuffer(Endian.LE);
        ntlmNegotiate.write(ntlmBuffer);
        negTokenInit.setMechToken(ntlmBuffer.getCompactData());
        Buffer.PlainBuffer negTokenBuffer = new Buffer.PlainBuffer(Endian.LE);
        negTokenInit.write(negTokenBuffer);
        return negTokenBuffer.getCompactData();
    }
}
