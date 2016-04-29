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
package com.hierynomus.smbj.connection;

import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.protocol.commons.socket.SocketClient;
import com.hierynomus.smbj.Config;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.auth.NtlmAuthenticator;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.smb2.SMB2Dialect;
import com.hierynomus.smbj.smb2.SMB2MessageFlag;
import com.hierynomus.smbj.smb2.SMB2Packet;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.smbj.smb2.messages.SMB2NegotiateRequest;
import com.hierynomus.smbj.smb2.messages.SMB2NegotiateResponse;
import com.hierynomus.smbj.transport.PacketHandler;
import com.hierynomus.smbj.transport.tcp.DirectTcpPacketReader;
import com.hierynomus.smbj.transport.tcp.DirectTcpTransport;
import com.hierynomus.smbj.transport.PacketReader;
import com.hierynomus.smbj.transport.TransportException;
import com.hierynomus.smbj.transport.TransportLayer;
import com.hierynomus.spnego.NegTokenInit;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashSet;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.isSet;

/**
 * A connection to a server.
 */
public class Connection extends SocketClient implements AutoCloseable, PacketHandler {
    private static final Logger logger = LoggerFactory.getLogger(Connection.class);

    private ConnectionInfo connectionInfo;
    private Config config;
    private TransportLayer transport;
    private PacketReader packetReader;
    private Thread packetReaderThread;
    private ConcurrentHashMap<Long, Request> outstandingRequests = new ConcurrentHashMap<>();


    public Connection(Config config, TransportLayer transport) {
        super(transport.getDefaultPort());
        this.config = config;
        this.transport = transport;
    }

    private void negotiateDialect() throws TransportException {
        logger.info("Negotiating dialects {} with server {}", config.getSupportedDialects(), getRemoteHostname());
        SMB2Packet negotiatePacket = new SMB2NegotiateRequest(config.getSupportedDialects(), connectionInfo.getClientGuid());
        Future<SMB2Packet> send = send(negotiatePacket);
        SMB2Packet negotiateResponse = Futures.get(send, TransportException.Wrapper);
        if (!(negotiateResponse instanceof SMB2NegotiateResponse)) {
            throw new IllegalStateException("Expected a SMB2 NEGOTIATE Response, but got: " + negotiateResponse.getHeader().getMessageId());
        }
        SMB2NegotiateResponse resp = (SMB2NegotiateResponse) negotiateResponse;
        connectionInfo.negotiated(resp);
        logger.info("Negotiated dialect: {}", connectionInfo.getDialect());
    }

    /**
     * On connection establishment, also initializes the transport via {@link DirectTcpTransport#init}.
     */
    @Override
    protected void onConnect() throws IOException {
        super.onConnect();
        this.connectionInfo = new ConnectionInfo(config.getClientGuid(), getRemoteHostname());
        packetReader = new DirectTcpPacketReader(getInputStream(), this);
        packetReaderThread = new Thread(packetReader);
        packetReaderThread.start();
        transport.init(getInputStream(), getOutputStream());
        negotiateDialect();
        logger.debug("Connected to: {}", getRemoteHostname());
    }

    @Override
    public void close() throws Exception {
        super.disconnect();
    }

    public <T extends SMB2Packet> Future<T> send(SMB2Packet packet) throws TransportException {
        long messageId = connectionInfo.getSequenceWindow().get();
        packet.getHeader().setMessageId(messageId);
        Request request = new Request(messageId, UUID.randomUUID(), packet);
        outstandingRequests.put(messageId, request);
        transport.write(packet);
        return request.getFuture(null); // TODO cancel callback
    }

    /**
     * Authenticate the user on this connection in order to start a (new) session.
     *
     * @return a (new) Session that is authenticated for the user.
     */
    public Session authenticate(AuthenticationContext authContext) {
        // TODO hardcoded for now
        NtlmAuthenticator.Factory factory = new NtlmAuthenticator.Factory();
        try {
            NegTokenInit negTokenInit = new NegTokenInit().read(connectionInfo.getGssNegotiateToken());
            if (negTokenInit.getSupportedMechTypes().contains(new ASN1ObjectIdentifier(factory.getName()))) {
                NtlmAuthenticator ntlmAuthenticator = factory.create();
                long sessionId = ntlmAuthenticator.authenticate(this, authContext);
                return new Session(sessionId);
            }
        } catch (IOException e) {
            throw new SMBRuntimeException(e);
        }
        return null;
    }

    /**
     * Return the negotiated dialect for this connection.
     *
     * @return The negotiated dialect
     */
    public SMB2Dialect getNegotiatedDialect() {
        return connectionInfo.getDialect();
    }

    @Override
    public void handle(SMB2Packet packet) throws TransportException {
        long messageId = packet.getSequenceNumber();
        if (!outstandingRequests.containsKey(messageId)) {
            throw new TransportException("Received response with unknown sequence number <<" + messageId + ">>");
        }

        // [MS-SMB2].pdf 3.2.5.1.4 Granting Message Credits
        connectionInfo.getSequenceWindow().creditsGranted(packet.getHeader().getCreditResponse());

        Request request = outstandingRequests.get(messageId);

        // [MS-SMB2].pdf 3.2.5.1.5 Handling Asynchronous Responses
        if (isSet(request.getRequestPacket().getHeader().getFlags(), SMB2MessageFlag.SMB2_FLAGS_ASYNC_COMMAND)) {
            if (packet.getHeader().getStatus() == NtStatus.STATUS_PENDING) {
                request.setAsyncId(packet.getHeader().getAsyncId());
                // TODO Expiration timer
                return;
            }
        }

        // [MS-SMB2].pdf 3.2.5.1.6 Handling Session Expiration
        if (packet.getHeader().getStatus() == NtStatus.STATUS_NETWORK_SESSION_EXPIRED) {
            // TODO reauthenticate session!
            return;
        }

        // [MS-SMB2].pdf 3.2.5.1.8 Processing the Response
        outstandingRequests.remove(messageId).getPromise().deliver(packet);
    }

    @Override
    public void handleError(Throwable t) {
        for (Long id : new HashSet<>(outstandingRequests.keySet())) {
            outstandingRequests.remove(id).getPromise().deliverError(t);
        }
    }
}
