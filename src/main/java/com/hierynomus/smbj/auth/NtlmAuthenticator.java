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

import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import com.hierynomus.ntlm.functions.NtlmFunctions;
import com.hierynomus.ntlm.functions.NtlmV2Functions;
import com.hierynomus.ntlm.messages.*;
import com.hierynomus.protocol.commons.ByteArrayUtils;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.connection.ConnectionContext;
import com.hierynomus.spnego.NegTokenInit;
import com.hierynomus.spnego.NegTokenTarg;
import com.hierynomus.spnego.SpnegoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Random;
import java.util.Set;

import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.*;

public class NtlmAuthenticator implements Authenticator {
    enum State { NEGOTIATE, AUTHENTICATE, COMPLETE; };

    private static final Logger logger = LoggerFactory.getLogger(NtlmAuthenticator.class);

    // The OID for NTLMSSP
    private static final ASN1ObjectIdentifier NTLMSSP = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.2.10");
    private SecurityProvider securityProvider;
    private Random random;

    private String workStationName;
    private State state;
    private Set<NtlmNegotiateFlag> negotiateFlags;
    private WindowsVersion windowsVersion;

    public static class Factory implements com.hierynomus.protocol.commons.Factory.Named<Authenticator> {
        @Override
        public String getName() {
            return NTLMSSP.getValue();
        }

        @Override
        public NtlmAuthenticator create() {
            return new NtlmAuthenticator();
        }
    }


    @Override
    public AuthenticateResponse authenticate(final AuthenticationContext context, final byte[] gssToken,
            ConnectionContext connectionContext) throws IOException {
        try {
            AuthenticateResponse response = new AuthenticateResponse();
            if (this.state == State.COMPLETE) {
                return null;
            } else if (this.state == State.NEGOTIATE) {
                logger.debug("Initialized Authentication of {} using NTLM", context.getUsername());
                return doNegotiate(context, gssToken);
            } else {
                logger.debug("Received token: {}", ByteArrayUtils.printHex(gssToken));
                NtlmV2Functions ntlmFunctions = new NtlmV2Functions(random, securityProvider);
                NegTokenTarg negTokenTarg = new NegTokenTarg().read(gssToken);
                BigInteger negotiationResult = negTokenTarg.getNegotiationResult();
                NtlmChallenge serverNtlmChallenge = new NtlmChallenge();
                try {
                    serverNtlmChallenge.read(new Buffer.PlainBuffer(negTokenTarg.getResponseToken(), Endian.LE));
                } catch (Buffer.BufferException e) {
                    throw new IOException(e);
                }
                logger.debug("Received NTLM challenge from: {}", serverNtlmChallenge.getTargetName());

                response.setWindowsVersion(serverNtlmChallenge.getVersion());
                response.setNetBiosName(serverNtlmChallenge.getTargetInfo().getAvPairString(AvId.MsvAvNbComputerName));

                byte[] serverChallenge = serverNtlmChallenge.getServerChallenge();
                byte[] responseKeyNT = ntlmFunctions.NTOWFv2(String.valueOf(context.getPassword()),
                        context.getUsername(), context.getDomain());

                TargetInfo clientTargetInfo = createClientTargetInfo(serverNtlmChallenge);
                byte[] ntlmv2ClientChallenge = ntlmFunctions.clientChallenge(clientTargetInfo);
                byte[] ntlmv2Response = ntlmFunctions.getNTLMv2Response(responseKeyNT, serverChallenge,
                        ntlmv2ClientChallenge);
                byte[] sessionkey;

                EnumSet<NtlmNegotiateFlag> negotiateFlags = serverNtlmChallenge.getNegotiateFlags();

                byte[] userSessionKey = NtlmFunctions.hmac_md5(securityProvider, responseKeyNT,
                        Arrays.copyOfRange(ntlmv2Response, 0, 16)); // first 16 bytes of ntlmv2Response is ntProofStr
                if (negotiateFlags.contains(NTLMSSP_NEGOTIATE_KEY_EXCH)
                        && (negotiateFlags.contains(NTLMSSP_NEGOTIATE_SIGN)
                                || negotiateFlags.contains(NTLMSSP_NEGOTIATE_SEAL)
                                || negotiateFlags.contains(NTLMSSP_NEGOTIATE_ALWAYS_SIGN))) {
                    byte[] masterKey = new byte[16];
                    random.nextBytes(masterKey);
                    sessionkey = NtlmFunctions.rc4k(securityProvider, userSessionKey, masterKey);
                    response.setSessionKey(masterKey);
                } else {
                    sessionkey = userSessionKey;
                    response.setSessionKey(sessionkey);
                }

                this.state = State.COMPLETE;
                // If NTLM v2 is used, KeyExchangeKey MUST be set to the given 128-bit
                // SessionBaseKey value.

                Object msAvTimestamp = serverNtlmChallenge.getTargetInfo().getAvPairObject(AvId.MsvAvTimestamp);
                if (msAvTimestamp != null) {
                    // negotiateFlags.add(NTLMSSP_NEGOTIATE_VERSION);
                    // MIC should be calculated
                    NtlmAuthenticate resp = new NtlmAuthenticate(new byte[0], ntlmv2Response,
                            context.getUsername(), context.getDomain(), workStationName, sessionkey,
                            EnumWithValue.EnumUtils.toLong(negotiateFlags),
                            true);

                    // TODO correct hash should be tested

                    Buffer.PlainBuffer concatenatedBuffer = new Buffer.PlainBuffer(Endian.LE);
                    concatenatedBuffer.putRawBytes(negTokenTarg.getResponseToken()); // negotiateMessage
                    concatenatedBuffer.putRawBytes(serverNtlmChallenge.getServerChallenge()); // challengeMessage
                    resp.writeAutentificateMessage(concatenatedBuffer); // authentificateMessage

                    byte[] mic = NtlmFunctions.hmac_md5(securityProvider, userSessionKey, concatenatedBuffer.getCompactData());
                    resp.setMic(mic);
                    response.setNegToken(negTokenTarg(resp));
                    return response;
                } else {
                    NtlmAuthenticate resp = new NtlmAuthenticate(new byte[0], ntlmv2Response,
                            context.getUsername(), context.getDomain(), workStationName, sessionkey,
                            EnumWithValue.EnumUtils.toLong(negotiateFlags),
                            false);
                    response.setNegToken(negTokenTarg(resp));
                    return response;
                }
            }
        } catch (SpnegoException spne) {
            throw new SMBRuntimeException(spne);
        }
    }

    private AuthenticateResponse doNegotiate(AuthenticationContext context, byte[] gssToken) throws SpnegoException {
        AuthenticateResponse response = new AuthenticateResponse();
        this.negotiateFlags = EnumSet.of(NTLMSSP_NEGOTIATE_128, NTLMSSP_REQUEST_TARGET,
                NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY);
        if (!context.isAnonymous()) {
            this.negotiateFlags.add(NTLMSSP_NEGOTIATE_SIGN);
            this.negotiateFlags.add(NTLMSSP_NEGOTIATE_ALWAYS_SIGN);
            this.negotiateFlags.add(NTLMSSP_NEGOTIATE_KEY_EXCH);
        } else if (context.isGuest()) {
            this.negotiateFlags.add(NTLMSSP_NEGOTIATE_KEY_EXCH);
        } else {
            this.negotiateFlags.add(NTLMSSP_NEGOTIATE_ANONYMOUS);
        }

        if (context.getDomain() != null && !context.getDomain().isEmpty()) {
            this.negotiateFlags.add(NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED);
        }

        if (this.workStationName != null && !this.workStationName.isEmpty()) {
            this.negotiateFlags.add(NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED);
        }

        NtlmNegotiate ntlmNegotiate = new NtlmNegotiate(negotiateFlags, workStationName, context.getDomain(), windowsVersion);
        this.state = State.AUTHENTICATE;
        response.setNegToken(negTokenInit(ntlmNegotiate));
        return response;
    }

    private TargetInfo createClientTargetInfo(NtlmChallenge serverNtlmChallenge) {
        TargetInfo clientTargetInfo = serverNtlmChallenge.getTargetInfo().copy();
        // MIC (16 bytes) provided if MsAvTimestamp is present
        if (serverNtlmChallenge.getTargetInfo().hasAvPair(AvId.MsvAvTimestamp)) {
            // Set MsAvFlags bit 0x2 to indicate that the client is providing a MIC
            if (clientTargetInfo.hasAvPair(AvId.MsvAvFlags)) {
                long flags = (long) clientTargetInfo.getAvPairObject(AvId.MsvAvFlags);
                flags = flags | 0x2;
                clientTargetInfo.putAvPairObject(AvId.MsvAvFlags, flags);
            } else {
                clientTargetInfo.putAvPairObject(AvId.MsvAvFlags, 0x2L);
            }
        }

        if (serverNtlmChallenge.getNegotiateFlags().contains(NTLMSSP_REQUEST_TARGET)) {
            clientTargetInfo.putAvPairString(AvId.MsvAvTargetName,
                    String.format("cifs/%s", clientTargetInfo.getAvPairString(AvId.MsvAvDnsComputerName)));
        }

        return clientTargetInfo;
    }

    private byte[] negTokenInit(NtlmNegotiate ntlmNegotiate) throws SpnegoException {
        NegTokenInit negTokenInit = new NegTokenInit();
        negTokenInit.addSupportedMech(NTLMSSP);
        Buffer.PlainBuffer ntlmBuffer = new Buffer.PlainBuffer(Endian.LE);
        ntlmNegotiate.write(ntlmBuffer);
        negTokenInit.setMechToken(ntlmBuffer.getCompactData());
        Buffer.PlainBuffer negTokenBuffer = new Buffer.PlainBuffer(Endian.LE);
        negTokenInit.write(negTokenBuffer);
        return negTokenBuffer.getCompactData();
    }

    private byte[] negTokenTarg(NtlmAuthenticate resp) throws SpnegoException {
        NegTokenTarg targ = new NegTokenTarg();
        Buffer.PlainBuffer ntlmBuffer = new Buffer.PlainBuffer(Endian.LE);
        resp.write(ntlmBuffer);
        targ.setResponseToken(ntlmBuffer.getCompactData());
        Buffer.PlainBuffer negTokenBuffer = new Buffer.PlainBuffer(Endian.LE);
        targ.write(negTokenBuffer);
        return negTokenBuffer.getCompactData();
    }

    @Override
    public void init(SmbConfig config) {
        this.securityProvider = config.getSecurityProvider();
        this.random = config.getRandomProvider();
        this.workStationName = config.getWorkStationName();
        this.windowsVersion = config.getWindowsVersion();
        this.state = State.NEGOTIATE;
    }

    @Override
    public boolean supports(AuthenticationContext context) {
        return context.getClass().equals(AuthenticationContext.class);
    }

}
