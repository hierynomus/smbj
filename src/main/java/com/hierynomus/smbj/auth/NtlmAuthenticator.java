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

import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_128;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_ANONYMOUS;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_KEY_EXCH;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SEAL;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SIGN;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_TARGET_INFO;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_REQUEST_TARGET;

import java.io.IOException;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import java.util.function.Predicate;

import com.hierynomus.msdtyp.FileTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import com.hierynomus.msdtyp.MsDataTypes;
import com.hierynomus.ntlm.NtlmException;
import com.hierynomus.ntlm.functions.ComputedNtlmV2Response;
import com.hierynomus.ntlm.functions.NtlmFunctions;
import com.hierynomus.ntlm.functions.NtlmV2Functions;
import com.hierynomus.ntlm.messages.AvId;
import com.hierynomus.ntlm.messages.NtlmAuthenticate;
import com.hierynomus.ntlm.messages.NtlmChallenge;
import com.hierynomus.ntlm.messages.NtlmNegotiate;
import com.hierynomus.ntlm.messages.NtlmNegotiateFlag;
import com.hierynomus.ntlm.messages.TargetInfo;
import com.hierynomus.ntlm.messages.WindowsVersion;
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
    enum State { NEGOTIATE, AUTHENTICATE, COMPLETE; };

    private static final Logger logger = LoggerFactory.getLogger(NtlmAuthenticator.class);

    // The OID for NTLMSSP
    private static final ASN1ObjectIdentifier NTLMSSP = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.2.10");
    private SecurityProvider securityProvider;
    private Random random;
    private NtlmV2Functions functions;
    private String workStationName;

    // Context buildup
    private State state;
    private Set<NtlmNegotiateFlag> negotiateFlags;
    private WindowsVersion windowsVersion;
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
    public AuthenticateResponse authenticate(final AuthenticationContext context, final byte[] gssToken,
            ConnectionContext connectionContext) throws IOException {
        try {
            if (this.state == State.COMPLETE) {
                return null;
            } else if (this.state == State.NEGOTIATE) {
                logger.debug("Initialized Authentication of {} using NTLM", context.getUsername());
                this.state = State.AUTHENTICATE;
                return doNegotiate(context, gssToken);
            } else {
                logger.debug("Received token: {}", ByteArrayUtils.printHex(gssToken));
                NegTokenTarg negTokenTarg = new NegTokenTarg().read(gssToken);
                NtlmChallenge serverNtlmChallenge = new NtlmChallenge();
                try {
                    serverNtlmChallenge.read(new Buffer.PlainBuffer(negTokenTarg.getResponseToken(), Endian.LE));
                } catch (Buffer.BufferException e) {
                    throw new IOException(e);
                }
                logger.trace("Received NTLM challenge: {}", serverNtlmChallenge);
                logger.debug("Received NTLM challenge from: {}", serverNtlmChallenge.getTargetName());

                // Only keep the negotiate flags that the server indicated it supports
                this.negotiateFlags.removeIf(new Predicate<NtlmNegotiateFlag>() {
                    @Override
                    public boolean test(NtlmNegotiateFlag ntlmNegotiateFlag) {
                        return !serverNtlmChallenge.getNegotiateFlags().contains(ntlmNegotiateFlag);
                    }
                });

                if (!this.negotiateFlags.contains(NTLMSSP_NEGOTIATE_128)) {
                    throw new NtlmException("Server does not support 128-bit encryption");
                }

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

        this.negotiateMessage = new NtlmNegotiate(negotiateFlags, workStationName, context.getDomain(), windowsVersion);
        logger.trace("Sending NTLM negotiate message: {}", this.negotiateMessage);
        response.setNegToken(negTokenInit(negotiateMessage));
        return response;
    }

    private AuthenticateResponse doAuthenticate(AuthenticationContext context, NtlmChallenge serverNtlmChallenge, byte[] ntlmChallengeBytes) throws SpnegoException {
        AuthenticateResponse response = new AuthenticateResponse();
        response.setWindowsVersion(serverNtlmChallenge.getVersion());
        response.setNetBiosName(serverNtlmChallenge.getTargetInfo().getAvPairString(AvId.MsvAvNbComputerName));

        // [MS-NLMP] 3.2.2 -- Special case for anonymous authentication
        if (context.isAnonymous()) {
            NtlmAuthenticate msg = new NtlmAuthenticate(null, null, context.getUsername(), context.getDomain(), workStationName, null, negotiateFlags, windowsVersion);
            response.setNegToken(negTokenTarg(msg));
            return response;
        }

        // Ensure we set TARGET_INFO
        negotiateFlags.add(NTLMSSP_NEGOTIATE_TARGET_INFO);
        TargetInfo clientTargetInfo = createClientTargetInfo(serverNtlmChallenge);

        long time = FileTime.now().getWindowsTimeStamp();
        if (clientTargetInfo.hasAvPair(AvId.MsvAvTimestamp)) {
            time = ((FileTime) clientTargetInfo.getAvPairObject(AvId.MsvAvTimestamp)).getWindowsTimeStamp();
        }
        ComputedNtlmV2Response computedNtlmV2Response = functions.computeResponse(context.getUsername(), context.getDomain(), context.getPassword(), serverNtlmChallenge, time, clientTargetInfo);

        byte[] sessionBaseKey = computedNtlmV2Response.getSessionBaseKey();
        byte[] ntResponse = computedNtlmV2Response.getNtResponse();
        byte[] lmResponse = computedNtlmV2Response.getLmResponse();
        if (serverNtlmChallenge.getTargetInfo().hasAvPair(AvId.MsvAvTimestamp)) {
            lmResponse = new byte[24];
        }

        byte[] encryptedRandomSessionKey;
        byte[] exportedSessionKey;
        byte[] keyExchangeKey = functions.kxKey(sessionBaseKey, computedNtlmV2Response.getLmResponse(), serverNtlmChallenge.getServerChallenge());
        Set<NtlmNegotiateFlag> serverFlags = serverNtlmChallenge.getNegotiateFlags();
        if (serverFlags.contains(NTLMSSP_NEGOTIATE_KEY_EXCH) && (serverFlags.contains(NTLMSSP_NEGOTIATE_SEAL) || serverFlags.contains(NTLMSSP_NEGOTIATE_SIGN))) {
            exportedSessionKey = new byte[16];
            random.nextBytes(exportedSessionKey);
            encryptedRandomSessionKey = NtlmFunctions.rc4k(securityProvider, keyExchangeKey, exportedSessionKey);
        } else {
            exportedSessionKey = keyExchangeKey;
            encryptedRandomSessionKey = null;
        }

        // TODO client/server signing/sealing keys

        NtlmAuthenticate msg = new NtlmAuthenticate(lmResponse, ntResponse, context.getUsername(), context.getDomain(), workStationName, encryptedRandomSessionKey, negotiateFlags, windowsVersion);
        if (serverNtlmChallenge.getTargetInfo().hasAvPair(AvId.MsvAvTimestamp)) {
            // Calculate MIC
            Buffer.PlainBuffer micBuffer = new Buffer.PlainBuffer(Endian.LE);
            negotiateMessage.write(micBuffer);
            micBuffer.putRawBytes(ntlmChallengeBytes);
            msg.write(micBuffer);
            byte[] mic = NtlmFunctions.hmac_md5(securityProvider, exportedSessionKey, micBuffer.getCompactData());
            msg.setMic(mic);
        }
        response.setSessionKey(exportedSessionKey);
        logger.trace("Sending NTLM authenticate message: {}", msg);
        response.setNegToken(negTokenTarg(msg));

        return response;
    }

    private TargetInfo createClientTargetInfo(NtlmChallenge serverNtlmChallenge) {
        TargetInfo clientTargetInfo = serverNtlmChallenge.getTargetInfo().copy();
        // MIC (16 bytes) provided if MsAvTimestamp is present
        if (serverNtlmChallenge.getTargetInfo().hasAvPair(AvId.MsvAvTimestamp)) {
//            // Set MsAvFlags bit 0x2 to indicate that the client is providing a MIC
//            if (clientTargetInfo.hasAvPair(AvId.MsvAvFlags)) {
//                long flags = (long) clientTargetInfo.getAvPairObject(AvId.MsvAvFlags);
//                flags = flags | 0x2;
//                clientTargetInfo.putAvPairObject(AvId.MsvAvFlags, flags);
//            } else {
//                clientTargetInfo.putAvPairObject(AvId.MsvAvFlags, 0x2L);
//            }
        }

        // Should be clientSuppliedeTargetName
        if (serverNtlmChallenge.getNegotiateFlags().contains(NTLMSSP_REQUEST_TARGET)) {
            clientTargetInfo.putAvPairString(AvId.MsvAvTargetName,
                    String.format("cifs/%s", clientTargetInfo.getAvPairString(AvId.MsvAvDnsComputerName)));
        } else {
            clientTargetInfo.putAvPairString(AvId.MsvAvTargetName, "");
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
        this.workStationName = config.getNtlmConfig().getWorkstationName();
        this.windowsVersion = config.getNtlmConfig().getWindowsVersion();
        this.state = State.NEGOTIATE;
        this.negotiateFlags = new HashSet<>();
        this.functions = new NtlmV2Functions(random, securityProvider);
    }

    @Override
    public boolean supports(AuthenticationContext context) {
        return context.getClass().equals(AuthenticationContext.class);
    }

}
