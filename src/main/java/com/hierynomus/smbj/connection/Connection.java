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

import com.hierynomus.protocol.commons.Base64;
import com.hierynomus.protocol.commons.ByteArrayUtils;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2MessageFlag;
import com.hierynomus.mssmb2.SMB2MultiCreditPacket;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.messages.SMB2NegotiateRequest;
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.protocol.commons.socket.SocketClient;
import com.hierynomus.smbj.Config;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.auth.NtlmAuthenticator;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.common.SMBException;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.event.SessionLoggedOff;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.PacketReader;
import com.hierynomus.smbj.transport.PacketReceiver;
import com.hierynomus.smbj.transport.TransportException;
import com.hierynomus.smbj.transport.TransportLayer;
import com.hierynomus.smbj.transport.tcp.DirectTcpPacketReader;
import com.hierynomus.smbj.transport.tcp.DirectTcpTransport;
import com.hierynomus.spnego.NegTokenInit;
import net.engio.mbassy.listener.Handler;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.util.NoSuchElementException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.UUID;
import java.util.concurrent.Future;
import java.util.concurrent.locks.ReentrantLock;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.isSet;
import static com.hierynomus.smbj.connection.NegotiatedProtocol.SINGLE_CREDIT_PAYLOAD_SIZE;

/**
 * A connection to a server.
 */
public class Connection extends SocketClient implements AutoCloseable, PacketReceiver<SMB2Packet> {
    private static final Logger logger = LoggerFactory.getLogger(Connection.class);
    private ConnectionInfo connectionInfo;

    private Config config;
    private TransportLayer transport;
    private final SMBEventBus bus;
    private PacketReader packetReader;
    private Thread packetReaderThread;
    private final ReentrantLock lock = new ReentrantLock();

    public Connection(Config config, TransportLayer transport, SMBEventBus bus) {
        super(transport.getDefaultPort());
        this.config = config;
        this.transport = transport;
        this.bus = bus;
        bus.subscribe(this);
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
        logger.info("Successfully connected to: {}", getRemoteHostname());
    }

    @Override
    public void close() throws Exception {
        connectionInfo.getSessionTable().closeRemainingSessions();
        packetReader.stop();
        logger.info("Closed connection to {}", getRemoteHostname());
        super.disconnect();
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
                Session session = ntlmAuthenticator.authenticate(this, authContext, bus);
                logger.info("Successfully authenticated {} on {}, session is {}", authContext.getUsername(), getRemoteHostname(), session.getSessionId());
                connectionInfo.getSessionTable().registerSession(session.getSessionId(), session);
                return session;
            }
        } catch (IOException e) {
            throw new SMBRuntimeException(e);
        }
        return null;
    }

    public <T extends SMB2Packet> Future<T> send(SMB2Packet packet) throws TransportException {
        lock.lock();
        try {
            int availableCredits = connectionInfo.getSequenceWindow().available();
            int grantCredits;
            if (packet instanceof SMB2MultiCreditPacket) {
                int payloadSize = ((SMB2MultiCreditPacket) packet).getPayloadSize();
                int creditsNeeded = creditsNeeded(payloadSize);
                // Scale the credits granted to the message dynamically.
                if (availableCredits == 0) {
                    throw new NoSuchElementException("TODO ([MS-SMB2].pdf 3.2.5.1.4 Granting Message Credits)! No credits left.");
                } else if (creditsNeeded < availableCredits) {
                    grantCredits = creditsNeeded;
                } else if (creditsNeeded > 1 && availableCredits > 1) { // creditsNeeded >= availableCredits
                    grantCredits = availableCredits - 1; // Keep 1 credit left for a simple request
                } else {
                    grantCredits = 1;
                }
                long[] messageIds = connectionInfo.getSequenceWindow().get(grantCredits);
                ((SMB2MultiCreditPacket) packet).setCreditsAssigned(grantCredits);
                packet.getHeader().setMessageId(messageIds[0]);
                logger.debug("Granted {} credits to {} with message id << {} >>", grantCredits, packet.getHeader().getMessage(), packet.getHeader().getMessageId());
            } else {
                grantCredits = 1;
                long messageId = connectionInfo.getSequenceWindow().get();
                packet.getHeader().setMessageId(messageId);
            }
            packet.getHeader().setCreditRequest(Math.max(SequenceWindow.PREFERRED_MINIMUM_CREDITS - availableCredits - grantCredits, grantCredits));

            Request request = new Request(packet.getHeader().getMessageId(), UUID.randomUUID(), packet);
            connectionInfo.getOutstandingRequests().registerOutstanding(request);
            if (connectionInfo.isRequireSigning() && packet.getHeader().getSessionId() > 0) {
                Session session = connectionInfo.getSessionTable().lookup(packet.getHeader().getSessionId());
                if (session != null) {
                    packet.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_SIGNED);
                    SMBBuffer buffer = new SMBBuffer();
                    packet.write(buffer);
                    Mac sha256_HMAC = null;
                    try {
                        sha256_HMAC = Mac.getInstance("HMACSHA256");

                        System.out.println("Session Key" + ByteArrayUtils.printHex(session.getSessionKey()));
                        SecretKeySpec secret_key = new SecretKeySpec(session.getSessionKey(), "HMACSHA256");
                        sha256_HMAC.init(secret_key);
                        byte[] dataToSign = buffer.getCompactData();
                        byte[] signature = sha256_HMAC.doFinal(dataToSign);
                        packet.getHeader().setSignature(signature);
                    } catch (Exception e) {
                        throw new TransportException(e);
                    }
                }
            }
            transport.write(packet);
            return request.getFuture(null); // TODO cancel callback
        } finally {
            lock.unlock();
        }
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
        logger.info("Negotiated the following connection settings: {}", connectionInfo);
    }


    /**
     * [MS-SMB2].pdf 3.1.5.2 Calculating the CreditCharge
     */
    private int creditsNeeded(int payloadSize) {
        return Math.abs((payloadSize - 1) / SINGLE_CREDIT_PAYLOAD_SIZE) + 1;
    }

    /**
     * Returns the negotiated protocol details for this connection.
     *
     * @return The negotiated protocol details
     */
    public NegotiatedProtocol getNegotiatedProtocol() {
        return connectionInfo.getNegotiatedProtocol();
    }

    @Override
    public void handle(SMB2Packet packet) throws TransportException {
        long messageId = packet.getSequenceNumber();
        if (!connectionInfo.getOutstandingRequests().isOutstanding(messageId)) {
            throw new TransportException("Received response with unknown sequence number <<" + messageId + ">>");
        }

        // [MS-SMB2].pdf 3.2.5.1.4 Granting Message Credits
        connectionInfo.getSequenceWindow().creditsGranted(packet.getHeader().getCreditResponse());
        logger.debug("Server granted us {} credits for message with sequence number << {} >>", packet.getHeader().getCreditResponse(), messageId);

        Request request = connectionInfo.getOutstandingRequests().getRequestByMessageId(messageId);
        logger.trace("Send/Recv of packet with message id << {} >> took << {} ms >>", messageId, System.currentTimeMillis() - request.getTimestamp().getTime());

        // [MS-SMB2].pdf 3.2.5.1.5 Handling Asynchronous Responses
        if (isSet(packet.getHeader().getFlags(), SMB2MessageFlag.SMB2_FLAGS_ASYNC_COMMAND)) {
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
        connectionInfo.getOutstandingRequests().receivedResponseFor(messageId).getPromise().deliver(packet);
    }

    @Override
    public void handleError(Throwable t) {
        connectionInfo.getOutstandingRequests().handleError(t);
    }


    @Handler
    private void sessionLogoff(SessionLoggedOff loggedOff) {
        connectionInfo.getSessionTable().sessionClosed(loggedOff.getSessionId());
        logger.debug("Session << {} >> logged off", loggedOff.getSessionId());
    }
}
