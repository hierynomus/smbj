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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.encodingrules.der.DEREncoder;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import com.hierynomus.ntlm.functions.NtlmFunctions;
import com.hierynomus.ntlm.messages.NtlmNegotiateFlag;
import com.hierynomus.ntlm.messages.WindowsVersion;
import com.hierynomus.ntlm.messages.WindowsVersion.NtlmRevisionCurrent;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.connection.ConnectionContext;
import com.hierynomus.spnego.NegTokenInit;
import com.hierynomus.spnego.NegTokenTarg;

public class NtlmSealer implements Authenticator {
    private static final Logger logger = LoggerFactory.getLogger(NtlmSealer.class);
    private static final byte[] C2S_SIGN_CONSTANT = "session key to client-to-server signing key magic constant\0"
            .getBytes(StandardCharsets.US_ASCII);
    private static final byte[] C2S_SEAL_CONSTANT = "session key to client-to-server sealing key magic constant\0"
            .getBytes(StandardCharsets.US_ASCII);

    private NtlmAuthenticator wrapped;
    private SecurityProvider securityProvider;

    private byte[] signKey;
    private byte[] sealKey;
    private AtomicInteger sequenceNumber = new AtomicInteger(0);
    private List<ASN1ObjectIdentifier> mechTypes;

    public NtlmSealer(NtlmAuthenticator wrapped) {
        this.wrapped = wrapped;
    }

    @Override
    public AuthenticateResponse authenticate(AuthenticationContext context, byte[] gssToken,
            ConnectionContext connectionContext) throws IOException {
        AuthenticateResponse resp = wrapped.authenticate(context, gssToken, connectionContext);
        if (resp == null) {
            return null;
        }

        byte[] sessionKey = resp.getSessionKey();
        Set<NtlmNegotiateFlag> negotiateFlags = resp.getNegotiateFlags();
        if (sessionKey != null) {
            logger.debug("Calculating signing and sealing keys for NTLM Extended Session Security");
            this.signKey = deriveSigningKey(sessionKey, negotiateFlags);
            this.sealKey = deriveSealingKey(sessionKey, negotiateFlags, resp.getWindowsVersion());
        }

        if (resp.getNegToken() instanceof NegTokenInit) {
            NegTokenInit negToken = (NegTokenInit) resp.getNegToken();
            mechTypes = negToken.getSupportedMechTypes();
        }

        if (signKey != null && resp.getNegToken() instanceof NegTokenTarg) {
            NegTokenTarg negToken = (NegTokenTarg) resp.getNegToken();
            logger.debug("Signing with NTLM Extended Session Security");
            int sequenceNumber = this.sequenceNumber.getAndIncrement();
            byte[] signature = sign(signKey, sequenceNumber);

            if (negotiateFlags.contains(NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_KEY_EXCH)) {
                signature = NtlmFunctions.rc4k(securityProvider, sealKey, signature);
            }

            Buffer<?> buffer = new SMBBuffer();
            buffer.putUInt32(1); // Version
            buffer.putRawBytes(signature, 0, 8); // Checksum
            buffer.putUInt32(sequenceNumber); // Sequence Number

            negToken.setMechListMic(buffer.getCompactData());
        }

        return resp;
    }

    private byte[] sign(byte[] signKey, int sequenceNumber) throws IOException {
        byte[] seq = uint32(sequenceNumber);
        byte[] data = derBytes(mechTypes);
        byte[] mac = NtlmFunctions.hmac_md5(securityProvider, signKey, seq, data);

        byte[] signature = new byte[8];
        System.arraycopy(mac, 0, signature, 0, 8);
        return signature;
    }

    private byte[] uint32(int value) {
        return new byte[] {
                (byte) (value & 0xFF),
                (byte) ((value >> 8) & 0xFF),
                (byte) ((value >> 16) & 0xFF),
                (byte) ((value >> 24) & 0xFF)
        };
    }

    @SuppressWarnings("rawtypes")
    private byte[] derBytes(List<ASN1ObjectIdentifier> mechTypes) throws IOException {
        List<ASN1Object> supportedMechVector = new ArrayList<ASN1Object>(mechTypes);
        ASN1Object o = new ASN1Sequence(supportedMechVector);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ASN1OutputStream out = new ASN1OutputStream(new DEREncoder(), baos)) {
            out.writeObject(o);
        }

        return baos.toByteArray();
    }

    private byte[] deriveSigningKey(byte[] sessionKey, Set<NtlmNegotiateFlag> negotiateFlags) {
        if (negotiateFlags.contains(NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)) {
            return NtlmFunctions.md5(securityProvider, sessionKey, C2S_SIGN_CONSTANT);
        }

        return null;
    }

    private byte[] deriveSealingKey(byte[] sessionKey, Set<NtlmNegotiateFlag> negotiateFlags,
            WindowsVersion windowsVersion) {
        byte[] tmpKey;
        if (negotiateFlags.contains(NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)) {
            if (negotiateFlags.contains(NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_128)) {
                tmpKey = sessionKey;
            } else if (negotiateFlags.contains(NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_56)) {
                tmpKey = Arrays.copyOf(sessionKey, 7);
            } else {
                tmpKey = Arrays.copyOf(sessionKey, 5);
            }

            return NtlmFunctions.md5(securityProvider, tmpKey, C2S_SEAL_CONSTANT);
        } else if (negotiateFlags.contains(NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_LM_KEY) ||
                (negotiateFlags.contains(NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_DATAGRAM) &&
                        windowsVersion.getNtlmRevision().getValue() >= NtlmRevisionCurrent.NTLMSSP_REVISION_W2K3
                                .getValue())) {
            tmpKey = new byte[8];
            if (negotiateFlags.contains(NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_56)) {
                System.arraycopy(sessionKey, 0, tmpKey, 0, 7);
                tmpKey[7] = (byte) 0xA0;
            } else {
                System.arraycopy(sessionKey, 0, tmpKey, 0, 5);
                tmpKey[5] = (byte) 0xE5;
                tmpKey[6] = (byte) 0x38;
                tmpKey[7] = (byte) 0xB0;
            }

            return tmpKey;
        } else {
            return Arrays.copyOf(sessionKey, sessionKey.length);
        }
    }

    @Override
    public void init(SmbConfig config) {
        wrapped.init(config);
        this.securityProvider = config.getSecurityProvider();
    }

    @Override
    public boolean supports(AuthenticationContext context) {
        return wrapped.supports(context);
    }
}
