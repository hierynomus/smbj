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

import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_56;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_128;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_ANONYMOUS;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_KEY_EXCH;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_NTLM;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SEAL;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SIGN;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_TARGET_INFO;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_UNICODE;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_REQUEST_TARGET;

import java.io.IOException;
import java.math.BigInteger;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import com.hierynomus.msdtyp.MsDataTypes;
import com.hierynomus.ntlm.NtlmConfig;
import com.hierynomus.ntlm.av.AvId;
import com.hierynomus.ntlm.av.AvPairFlags;
import com.hierynomus.ntlm.functions.ComputedNtlmV2Response;
import com.hierynomus.ntlm.functions.NtlmFunctions;
import com.hierynomus.ntlm.functions.NtlmV2Functions;
import com.hierynomus.ntlm.messages.NtlmAuthenticate;
import com.hierynomus.ntlm.messages.NtlmChallenge;
import com.hierynomus.ntlm.messages.NtlmNegotiate;
import com.hierynomus.ntlm.messages.NtlmNegotiateFlag;
import com.hierynomus.protocol.commons.ByteArrayUtils;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.connection.ConnectionContext;
import com.hierynomus.spnego.NegTokenInit;
import com.hierynomus.spnego.NegTokenTarg;
import com.hierynomus.spnego.SpnegoException;

public class NtlmAuthenticator implements Authenticator {
    enum State { NEGOTIATE, AUTHENTICATE, COMPLETE };

    private static final Logger logger = LoggerFactory.getLogger(NtlmAuthenticator.class);

    // The OID for NTLMSSP
    private static final ASN1ObjectIdentifier NTLMSSP = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.2.10");
    private SecurityProvider securityProvider;
    private Random random;
    private NtlmV2Functions functions;
    private NtlmConfig config;

    // Context buildup
    private State state;
    private Set<NtlmNegotiateFlag> negotiateFlags;
    private NtlmNegotiate negotiateMessage;

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
    public AuthenticateResponse authenticate(final AuthenticationContext context, final byte[] gssToken, ConnectionContext connectionContext) throws IOException {
        try {
            if (state == State.COMPLETE) {
                return null;
            } else if (state == State.NEGOTIATE) {
                logger.debug("Initialized Authentication of {} using NTLM", context.getUsername());
                this.state = State.AUTHENTICATE;
                return doNegotiate(context, gssToken);
            } else {
                logger.debug("Received token: {}", ByteArrayUtils.printHex(gssToken));
                NegTokenTarg negTokenTarg = new NegTokenTarg().read(gssToken);
                BigInteger negotiationResult = negTokenTarg.getNegotiationResult();
                NtlmChallenge serverNtlmChallenge = new NtlmChallenge();
                try {
                    serverNtlmChallenge.read(new Buffer.PlainBuffer(negTokenTarg.getResponseToken(), Endian.LE));
                } catch (Buffer.BufferException e) {
                    throw new IOException(e);
                }
                logger.trace("Received NTLM challenge: {}", serverNtlmChallenge);
                logger.debug("Received NTLM challenge from: {}", serverNtlmChallenge.getTargetName());

                AuthenticateResponse resp = doAuthenticate(context, serverNtlmChallenge, negTokenTarg.getResponseToken());
                this.state = State.COMPLETE;
                return resp;
            }
        } catch (SpnegoException spne) {
            throw new SMBRuntimeException(spne);
        }
    }

    private AuthenticateResponse doNegotiate(AuthenticationContext context, byte[] gssToken) throws SpnegoException {
        AuthenticateResponse response = new AuthenticateResponse();
        this.negotiateFlags = EnumSet.of(
            NTLMSSP_NEGOTIATE_56,
            NTLMSSP_NEGOTIATE_128,
            NTLMSSP_NEGOTIATE_TARGET_INFO,
            NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
            NTLMSSP_NEGOTIATE_SIGN,
            NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
            NTLMSSP_NEGOTIATE_KEY_EXCH,
            NTLMSSP_NEGOTIATE_NTLM,
            NTLMSSP_NEGOTIATE_NTLM,
            NTLMSSP_REQUEST_TARGET,
            NTLMSSP_NEGOTIATE_UNICODE);

        this.negotiateMessage = new NtlmNegotiate(negotiateFlags);
        logger.trace("Sending NTLM negotiate message: {}", this.negotiateMessage);
        response.setNegToken(negTokenInit(this.negotiateMessage));
        return response;
    }

    private AuthenticateResponse doAuthenticate(AuthenticationContext context, NtlmChallenge serverNtlmChallenge, byte[] responseToken) throws SpnegoException {
        AuthenticateResponse response = new AuthenticateResponse();
        response.setWindowsVersion(serverNtlmChallenge.getVersion());
        if (serverNtlmChallenge.getTargetInfo() != null && serverNtlmChallenge.getTargetInfo().hasAvPair(AvId.MsvAvNbComputerName)) {
            response.setNetBiosName((String) serverNtlmChallenge.getTargetInfo().getAvPair(AvId.MsvAvNbComputerName).getValue());
        }

        byte[] serverChallenge = serverNtlmChallenge.getServerChallenge();
        byte[] responseKeyNT = functions.NTOWFv2(String.valueOf(context.getPassword()),
                context.getUsername(), context.getDomain());
        ComputedNtlmV2Response computedNtlmV2Response = functions.computeResponse(context.getUsername(),
                context.getDomain(), context.getPassword(), serverNtlmChallenge, MsDataTypes.nowAsFileTime(),
                serverNtlmChallenge.getTargetInfo());
        // byte[] ntlmv2ClientChallenge = computedNtlmV2Response.getNtResponse();
        byte[] ntlmv2Response = computedNtlmV2Response.getNtResponse();
        byte[] sessionkey;

        byte[] userSessionKey = computedNtlmV2Response.getSessionBaseKey();
        EnumSet<NtlmNegotiateFlag> negotiateFlags = serverNtlmChallenge.getNegotiateFlags();
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

        // If NTLM v2 is used, KeyExchangeKey MUST be set to the given 128-bit
        // SessionBaseKey value.

        // MIC (16 bytes) provided if in AvPairType is key MsvAvFlags with value &
        // 0x00000002 is true
        AvPairFlags pair = serverNtlmChallenge.getTargetInfo() != null
                ? serverNtlmChallenge.getTargetInfo().getAvPair(AvId.MsvAvFlags)
                : null;
        if (pair != null && (pair.getValue() & 0x00000002) > 0) {
            // MIC should be calculated
            NtlmAuthenticate resp = new NtlmAuthenticate(new byte[0], ntlmv2Response,
                    context.getUsername(), context.getDomain(), config.getWorkstationName(), sessionkey, negotiateFlags, config.getWindowsVersion(),
                    true);

            // TODO correct hash should be tested

            Buffer.PlainBuffer concatenatedBuffer = new Buffer.PlainBuffer(Endian.LE);
            negotiateMessage.write(concatenatedBuffer); // negotiateMessage
            concatenatedBuffer.putRawBytes(serverNtlmChallenge.getServerChallenge()); // challengeMessage
            resp.writeAutentificateMessage(concatenatedBuffer); // authentificateMessage

            byte[] mic = NtlmFunctions.hmac_md5(securityProvider, userSessionKey,
                    concatenatedBuffer.getCompactData());
            resp.setMic(mic);
            response.setNegToken(negTokenTarg(resp));
            return response;
        } else {
            NtlmAuthenticate resp = new NtlmAuthenticate(new byte[0], ntlmv2Response,
                    context.getUsername(), context.getDomain(), config.getWorkstationName(), sessionkey, negotiateFlags, config.getWindowsVersion(),
                    false);
            response.setNegToken(negTokenTarg(resp));
            return response;
        }
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
        this.config = config.getNtlmConfig();
        this.state = State.NEGOTIATE;
        this.negotiateFlags = new HashSet<>();
        this.functions = new NtlmV2Functions(random, securityProvider);
    }

    @Override
    public boolean supports(AuthenticationContext context) {
        return context.getClass().equals(AuthenticationContext.class);
    }

}
