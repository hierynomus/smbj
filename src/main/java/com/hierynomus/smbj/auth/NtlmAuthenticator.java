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

import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_KEY_EXCH;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SEAL;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SIGN;

import java.io.IOException;
import java.math.BigInteger;
import java.util.EnumSet;
import java.util.Random;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import com.hierynomus.msdtyp.MsDataTypes;
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

public class NtlmAuthenticator implements Authenticator {
    private static final Logger logger = LoggerFactory.getLogger(NtlmAuthenticator.class);

    // The OID for NTLMSSP
    private static final ASN1ObjectIdentifier NTLMSSP = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.2.10");
    private SecurityProvider securityProvider;
    private Random random;
    private String workStationName;

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

    private boolean initialized = false;
    private boolean completed = false;

    @Override
    public AuthenticateResponse authenticate(final AuthenticationContext context, final byte[] gssToken, ConnectionContext connectionContext) throws IOException {
        try {
            AuthenticateResponse response = new AuthenticateResponse();
            if (completed) {
                return null;
            } else if (!initialized) {
                logger.debug("Initialized Authentication of {} using NTLM", context.getUsername());
                NtlmNegotiate ntlmNegotiate = new NtlmNegotiate();
                initialized = true;
                response.setNegToken(negTokenInit(ntlmNegotiate));
                return response;
            } else {
                logger.debug("Received token: {}", ByteArrayUtils.printHex(gssToken));
                NtlmV2Functions ntlmFunctions = new NtlmV2Functions(random, securityProvider);
                NegTokenTarg negTokenTarg = new NegTokenTarg().read(gssToken);
                BigInteger negotiationResult = negTokenTarg.getNegotiationResult();
                NtlmChallenge challenge = new NtlmChallenge();
                try {
                    challenge.read(new Buffer.PlainBuffer(negTokenTarg.getResponseToken(), Endian.LE));
                } catch (Buffer.BufferException e) {
                    throw new IOException(e);
                }
                logger.debug("Received NTLM challenge from: {}", challenge.getTargetName());

                response.setWindowsVersion(challenge.getVersion());
                if (challenge.getTargetInfo() != null && challenge.getTargetInfo().hasAvPair(AvId.MsvAvNbComputerName)) {
                    response.setNetBiosName((String) challenge.getTargetInfo().getAvPair(AvId.MsvAvNbComputerName).getValue());
                }

                byte[] serverChallenge = challenge.getServerChallenge();
                byte[] responseKeyNT = ntlmFunctions.NTOWFv2(String.valueOf(context.getPassword()),
                        context.getUsername(), context.getDomain());
                ComputedNtlmV2Response computedNtlmV2Response = ntlmFunctions.computeResponse(context.getUsername(), context.getDomain(), context.getPassword(), challenge, MsDataTypes.nowAsFileTime(), challenge.getTargetInfo());
                // byte[] ntlmv2ClientChallenge = computedNtlmV2Response.getNtResponse();
                byte[] ntlmv2Response = computedNtlmV2Response.getNtResponse();
                byte[] sessionkey;

                byte[] userSessionKey = computedNtlmV2Response.getSessionBaseKey();
                EnumSet<NtlmNegotiateFlag> negotiateFlags = challenge.getNegotiateFlags();
                if (negotiateFlags.contains(NTLMSSP_NEGOTIATE_KEY_EXCH)
                    && (negotiateFlags.contains(NTLMSSP_NEGOTIATE_SIGN)
                    || negotiateFlags.contains(NTLMSSP_NEGOTIATE_SEAL)
                    || negotiateFlags.contains(NTLMSSP_NEGOTIATE_ALWAYS_SIGN))
                    ) {
                    byte[] masterKey = new byte[16];
                    random.nextBytes(masterKey);
                    sessionkey = NtlmFunctions.rc4k(securityProvider, userSessionKey, masterKey);
                    response.setSessionKey(masterKey);
                } else {
                    sessionkey = userSessionKey;
                    response.setSessionKey(sessionkey);
                }

                completed = true;

                // If NTLM v2 is used, KeyExchangeKey MUST be set to the given 128-bit SessionBaseKey value.

                // MIC (16 bytes) provided if in AvPairType is key MsvAvFlags with value & 0x00000002 is true
                AvPairFlags pair = challenge.getTargetInfo() != null ? challenge.getTargetInfo().getAvPair(AvId.MsvAvFlags) : null;
                if (pair != null && (pair.getValue() & 0x00000002) > 0) {
                    // MIC should be calculated
                    NtlmAuthenticate resp = new NtlmAuthenticate(new byte[0], ntlmv2Response,
                        context.getUsername(), context.getDomain(), workStationName, sessionkey, EnumWithValue.EnumUtils.toLong(negotiateFlags),
                        true
                    );

                    // TODO correct hash should be tested

                    Buffer.PlainBuffer concatenatedBuffer = new Buffer.PlainBuffer(Endian.LE);
                    concatenatedBuffer.putRawBytes(negTokenTarg.getResponseToken()); //negotiateMessage
                    concatenatedBuffer.putRawBytes(challenge.getServerChallenge()); //challengeMessage
                    resp.writeAutentificateMessage(concatenatedBuffer); //authentificateMessage

                    byte[] mic = NtlmFunctions.hmac_md5(securityProvider, userSessionKey, concatenatedBuffer.getCompactData());
                    resp.setMic(mic);
                    response.setNegToken(negTokenTarg(resp, negTokenTarg.getResponseToken()));
                    return response;
                } else {
                    NtlmAuthenticate resp = new NtlmAuthenticate(new byte[0], ntlmv2Response,
                        context.getUsername(), context.getDomain(), workStationName, sessionkey, EnumWithValue.EnumUtils.toLong(negotiateFlags),
                        false
                    );
                    response.setNegToken(negTokenTarg(resp, negTokenTarg.getResponseToken()));
                    return response;
                }
            }
        } catch (SpnegoException spne) {
            throw new SMBRuntimeException(spne);
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

    private byte[] negTokenTarg(NtlmAuthenticate resp, byte[] responseToken) throws SpnegoException {
        NegTokenTarg targ = new NegTokenTarg();
        targ.setResponseToken(responseToken);
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
    }

    @Override
    public boolean supports(AuthenticationContext context) {
        return context.getClass().equals(AuthenticationContext.class);
    }

}
