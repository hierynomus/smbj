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
package com.hierynomus.smbj.testing;

import java.util.EnumSet;
import java.util.UUID;

import com.hierynomus.msdtyp.FileTime;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2Error;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2ShareCapabilities;
import com.hierynomus.mssmb2.SMB2ShareFlags;
import com.hierynomus.mssmb2.messages.SMB2Logoff;
import com.hierynomus.mssmb2.messages.SMB2NegotiateRequest;
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse;
import com.hierynomus.mssmb2.messages.SMB2SessionSetup;
import com.hierynomus.mssmb2.messages.SMB2TreeConnectResponse;
import com.hierynomus.mssmb2.messages.SMB2TreeDisconnect;

@FunctionalInterface
public interface PacketProcessor {
    SMB2Packet process(SMB2Packet request);

    default PacketProcessor wrap(PacketProcessor processor) {
        PacketProcessor self = this;
        return new PacketProcessor() {
            @Override
            public SMB2Packet process(SMB2Packet request) {
                SMB2Packet p = processor.process(request);
                if (p == null) {
                    return self.process(request);
                }
                return p;
            }
        };
    }

    public static class NoOpPacketProcessor implements PacketProcessor {
        @Override
        public SMB2Packet process(SMB2Packet request) {
            return null;
        }
    }

    public static class DefaultPacketProcessor implements PacketProcessor {
        @Override
        public SMB2Packet process(SMB2Packet request) {
            SMB2Packet resp = null;
            request = request.getPacket(); // Ensure unwrapping
            switch (request.getHeader().getMessage()) {
                case SMB2_NEGOTIATE:
                    resp = negotiateResponse((SMB2NegotiateRequest) request);
                    break;
                case SMB2_SESSION_SETUP:
                    resp = sessionSetupResponse((SMB2SessionSetup) request);
                    break;
                case SMB2_TREE_CONNECT:
                    resp = connectResponse();
                    break;
                case SMB2_TREE_DISCONNECT:
                    resp = disconnectResponse();
                    break;
                case SMB2_LOGOFF:
                    resp = logoffResponse();
                    break;
                default:
                    resp = error();
            }

            return resp;
        }

        private SMB2NegotiateResponse negotiateResponse(SMB2NegotiateRequest request) {
            SMB2NegotiateResponse response = new SMB2NegotiateResponse();
            response.getHeader().setMessageType(SMB2MessageCommandCode.SMB2_NEGOTIATE);
            response.getHeader().setStatusCode(NtStatus.STATUS_SUCCESS.getValue());
            response.setDialect(SMB2Dialect.SMB_2_1);
            response.setSystemTime(FileTime.now());
            response.setServerGuid(UUID.fromString("00112233-4455-6677-8899-aabbccddeeff"));
            return response;
        }

        private SMB2SessionSetup sessionSetupResponse(SMB2SessionSetup request) {
            SMB2SessionSetup response = new SMB2SessionSetup();
            response.getHeader().setMessageType(SMB2MessageCommandCode.SMB2_SESSION_SETUP);
            response.getHeader().setStatusCode(NtStatus.STATUS_SUCCESS.getValue());
            response.getHeader().setSessionId(1);
            response.setSecurityBuffer(new byte[16]);
            response.setSessionFlags(EnumSet.noneOf(SMB2SessionSetup.SMB2SessionFlags.class));
            return response;
        }

        private static SMB2Packet logoffResponse() {
            SMB2Logoff response = new SMB2Logoff();
            response.getHeader().setMessageType(SMB2MessageCommandCode.SMB2_LOGOFF);
            response.getHeader().setStatusCode(NtStatus.STATUS_SUCCESS.getValue());
            return response;
        }

        private static SMB2Packet connectResponse() {
            SMB2TreeConnectResponse response = new SMB2TreeConnectResponse();
            response.getHeader().setStatusCode(NtStatus.STATUS_SUCCESS.getValue());
            response.setCapabilities(EnumSet.of(SMB2ShareCapabilities.SMB2_SHARE_CAP_DFS));
            response.setShareFlags(EnumSet.noneOf(SMB2ShareFlags.class));
            response.setShareType((byte) 0x01);
            return response;
        }

        private static SMB2Packet disconnectResponse() {
            SMB2TreeDisconnect response = new SMB2TreeDisconnect();
            response.getHeader().setStatusCode(NtStatus.STATUS_SUCCESS.getValue());
            return response;
        }

        private static SMB2Packet error() {
            SMB2Packet p = new SMB2Packet();
            p.getHeader().setStatusCode(NtStatus.STATUS_INTERNAL_ERROR.getValue());
            p.setError(new SMB2Error());
            return p;
        }

    }
}
