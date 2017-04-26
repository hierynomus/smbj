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
package com.hierynomus.msdfsc;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.mssmb2.messages.SMB2CreateRequest;
import com.hierynomus.mssmb2.messages.SMB2TreeConnectRequest;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.PathResolveException;
import com.hierynomus.smbj.transport.TransportException;

import java.util.concurrent.Future;

/**
 * [MS-DFSC].pdf
 *
 * This class implements a DFS enabled Session, extending the 'default' SMB2Session class.
 */
public class DFSSession extends Session {
    private DFSPathResolver resolver = new DFSPathResolver();

    public DFSSession(long sessionId, Connection connection, AuthenticationContext auth, SMBEventBus bus, boolean signingRequired, SecurityProvider securityProvider) {
        super(sessionId, connection, auth, bus, signingRequired, securityProvider);
    }

    @Override
    public <T extends SMB2Packet> Future<T> send(SMB2Packet packet) throws TransportException {
        if (packet.getHeader().getMessage() == SMB2MessageCommandCode.SMB2_TREE_CONNECT) {
            resolveTreeConnect((SMB2TreeConnectRequest) packet);
        }
        return super.send(packet);
    }

    private void resolveTreeConnect(SMB2TreeConnectRequest packet) {
        try {
            packet.setSmbPath(SmbPath.parse(resolver.resolve(this, packet.getSmbPath().toUncPath())));
        } catch (PathResolveException e) {
            throw new SMBRuntimeException(e);
        }
    }

    @Override
    public <T extends SMB2Packet> T processSendResponse(SMB2CreateRequest packet) throws TransportException {
        while (true) {
            Future<T> responseFuture = send(packet);
            T response = Futures.get(responseFuture, SMBRuntimeException.Wrapper);
            if (response.getHeader().getStatus() == NtStatus.STATUS_PATH_NOT_COVERED) {
                try {
                    packet.setFileName(resolver.resolve(this, packet.getFileName()));
                    //resolve dfs, modify packet, resend packet to new target, and hopefully it works there
                } catch (PathResolveException e) { //TODO we wouldn't have to do this if we just threw SMBApiException from inside DFS
                    throw new SMBApiException(e.getStatus(), packet.getHeader().getMessage(), e);
                }
                // and we try again
            } else {
                return response;
            }
        }

    }

    public DFSPathResolver getResolver() {
        return resolver;
    }
}
