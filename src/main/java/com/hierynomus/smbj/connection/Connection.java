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

import com.hierynomus.msdfsc.DFSSession;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2MessageConverter;
import com.hierynomus.mssmb2.messages.SMB2NegotiateRequest;
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse;
import com.hierynomus.mssmb2.messages.SMB2SessionSetup;
import com.hierynomus.protocol.commons.Factory;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.protocol.commons.socket.SocketClient;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.auth.Authenticator;
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
import com.hierynomus.spnego.SpnegoException;
import net.engio.mbassy.listener.Handler;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import static com.hierynomus.mssmb2.SMB2Packet.SINGLE_CREDIT_PAYLOAD_SIZE;
import static com.hierynomus.mssmb2.messages.SMB2SessionSetup.SMB2SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED;
import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.isSet;
import static java.lang.String.format;

/**
 * A connection to a server.
 */
public class Connection extends SocketClient implements AutoCloseable, PacketReceiver<SMB2Packet> {
    private static final Logger logger = LoggerFactory.getLogger(Connection.class);
    private ConnectionInfo connectionInfo;

    private SMBClient client;

    public SMBClient getClient() {
        return client;
    }

    private SmbConfig config;
    private TransportLayer<SMB2Packet> transport;
    private final SMBEventBus bus;
    private PacketReader<SMB2Packet> packetReader;
    private final ReentrantLock lock = new ReentrantLock();

    public Connection(SmbConfig config, SMBClient client, SMBEventBus bus) {
        this(config, client, new DirectTcpTransport<SMB2Packet>(), bus);
    }

    private Connection(SmbConfig config, SMBClient client, TransportLayer<SMB2Packet> transport, SMBEventBus bus) {
        super(transport.getDefaultPort(), config.getSoTimeout(), config.getSocketFactory());
        this.config = config;
        this.client = client;
        this.transport = transport;
        this.bus = bus;
        bus.subscribe(this);
    }

    public Connection(Connection connection) {
        super(connection.defaultPort, connection.config.getSoTimeout(), connection.config.getSocketFactory());
        this.client = connection.client;
        this.config = connection.config;
        this.transport = connection.transport;
        this.bus = connection.bus;
        bus.subscribe(this);
    }

    /**
     * On connection establishment, also initializes the transport via {@link DirectTcpTransport#init}.
     */
    @Override
    protected void onConnect() throws IOException {
        super.onConnect();
        this.connectionInfo = new ConnectionInfo(config.getClientGuid(), getRemoteHostname());
        SMB2MessageConverter smb2MessageConverter = new SMB2MessageConverter();
        packetReader = new DirectTcpPacketReader<>(getRemoteHostname(), getInputStream(), smb2MessageConverter, this);
        packetReader.start();
        transport.init(getInputStream(), getOutputStream(), smb2MessageConverter);
        negotiateDialect();
        logger.info("Successfully connected to: {}", getRemoteHostname());
    }

    @Override
    public void close() throws Exception {
        for (Session session : connectionInfo.getSessionTable().activeSessions()) {
            try {
                session.close();
            } catch (IOException e) {
                logger.warn("Exception while closing session {}", session.getSessionId(), e);
            }
        }
        packetReader.stop();
        logger.info("Closed connection to {}", getRemoteHostname());
        super.disconnect();
    }

    public SmbConfig getConfig() {
        return config;
    }

    /**
     * Authenticate the user on this connection in order to start a (new) session.
     *
     * @return a (new) Session that is authenticated for the user.
     */
    public Session authenticate(AuthenticationContext authContext) {
        try {
            Authenticator authenticator = getAuthenticator(authContext);
            authenticator.init(config.getSecurityProvider(), config.getRandomProvider());
            Session session = getSession(authContext);
            SMB2SessionSetup receive = authenticationRound(authenticator, authContext, connectionInfo.getGssNegotiateToken(), session);
            long sessionId = receive.getHeader().getSessionId();
            session.setSessionId(sessionId);
            connectionInfo.getPreauthSessionTable().registerSession(sessionId, session);
            try {
                while (receive.getHeader().getStatus() == NtStatus.STATUS_MORE_PROCESSING_REQUIRED) {
                    logger.debug("More processing required for authentication of {} using {}", authContext.getUsername(), authenticator);
                    receive = authenticationRound(authenticator, authContext, receive.getSecurityBuffer(), session);
                }

                if (receive.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                    throw new SMBApiException(receive.getHeader(), format("Authentication failed for '%s' using %s", authContext.getUsername(), authenticator));
                }

                if (receive.getSecurityBuffer() != null) {
                    // process the last received buffer
                    authenticator.authenticate(authContext, receive.getSecurityBuffer(), session);
                }
                logger.info("Successfully authenticated {} on {}, session is {}", authContext.getUsername(), getRemoteHostname(), session.getSessionId());
                connectionInfo.getSessionTable().registerSession(session.getSessionId(), session);
                return session;
            } finally {
                connectionInfo.getPreauthSessionTable().sessionClosed(sessionId);
            }
        } catch (SpnegoException | IOException e) {
            throw new SMBRuntimeException(e);
        }
    }

    private Session getSession(AuthenticationContext authContext) {
        if (config.isDfsEnabled()) {
            return new DFSSession(0, this, authContext, bus, connectionInfo.isServerRequiresSigning(), config.getSecurityProvider());
        }
        return new Session(0, this, authContext, bus, connectionInfo.isServerRequiresSigning(), config.getSecurityProvider());
    }

    private SMB2SessionSetup authenticationRound(Authenticator authenticator, AuthenticationContext authContext, byte[] inputToken, Session session) throws IOException {
        byte[] securityContext = authenticator.authenticate(authContext, inputToken, session);

        SMB2SessionSetup req = new SMB2SessionSetup(connectionInfo.getNegotiatedProtocol().getDialect(), EnumSet.of(SMB2_NEGOTIATE_SIGNING_ENABLED), 
                connectionInfo.getClientCapabilities());
        req.setSecurityBuffer(securityContext);
        req.getHeader().setSessionId(session.getSessionId());
        return Futures.get(this.<SMB2SessionSetup>send(req), getConfig().getTransactTimeout(), TimeUnit.MILLISECONDS, TransportException.Wrapper);
    }

    private Authenticator getAuthenticator(AuthenticationContext context) throws IOException, SpnegoException {
        List<Factory.Named<Authenticator>> supportedAuthenticators = new ArrayList<>(config.getSupportedAuthenticators());
        List<ASN1ObjectIdentifier> mechTypes = new ArrayList<>();
        if (connectionInfo.getGssNegotiateToken().length > 0) {
            NegTokenInit negTokenInit = new NegTokenInit().read(connectionInfo.getGssNegotiateToken());
            mechTypes = negTokenInit.getSupportedMechTypes();
        }

        for (Factory.Named<Authenticator> factory : new ArrayList<>(supportedAuthenticators)) {
            if (mechTypes.isEmpty() || mechTypes.contains(new ASN1ObjectIdentifier(factory.getName()))) {
                Authenticator authenticator = factory.create();
                if (authenticator.supports(context)) {
                    return authenticator;
                }
            }
        }

        throw new SMBRuntimeException("Could not find a configured authenticator for mechtypes: " + mechTypes + " and authentication context: " + context);
    }

    /**
     * send a packet.
     *
     * @param packet SMBPacket to send
     * @return a Future to be used to retrieve the response packet
     * @throws TransportException When a transport level error occurred
     */
    public <T extends SMB2Packet> Future<T> send(SMB2Packet packet) throws TransportException {
        lock.lock();
        try {
            int availableCredits = connectionInfo.getSequenceWindow().available();
            int grantCredits = calculateGrantedCredits(packet, availableCredits);
            if (availableCredits == 0) {
                logger.warn("There are no credits left to send {}, will block until there are more credits available.", packet.getHeader().getMessage());
            }
            long[] messageIds = connectionInfo.getSequenceWindow().get(grantCredits);
            packet.getHeader().setMessageId(messageIds[0]);
            logger.debug("Granted {} (out of {}) credits to {}", grantCredits, availableCredits, packet);
            packet.getHeader().setCreditRequest(Math.max(SequenceWindow.PREFERRED_MINIMUM_CREDITS - availableCredits - grantCredits, grantCredits));

            Request request = new Request(packet.getHeader().getMessageId(), UUID.randomUUID(), packet);
            connectionInfo.getOutstandingRequests().registerOutstanding(request);
            transport.write(packet);
            return request.getFuture(null); // TODO cancel callback
        } finally {
            lock.unlock();
        }
    }

    private <T extends SMB2Packet> T sendAndReceive(SMB2Packet packet) throws TransportException {
        return Futures.get(this.<T>send(packet), getConfig().getTransactTimeout(), TimeUnit.MILLISECONDS, TransportException.Wrapper);
    }

    private int calculateGrantedCredits(final SMB2Packet packet, final int availableCredits) {
        final int grantCredits;
        int maxPayloadSize = packet.getMaxPayloadSize();
        int creditsNeeded = creditsNeeded(maxPayloadSize);
        if (creditsNeeded > 1 && !connectionInfo.supports(SMB2GlobalCapability.SMB2_GLOBAL_CAP_LARGE_MTU)) {
            logger.trace("Connection to {} does not support multi-credit requests.", getRemoteHostname());
            grantCredits = 1;
        } else if (creditsNeeded < availableCredits) { // Scale the credits dynamically
            grantCredits = creditsNeeded;
        } else if (creditsNeeded > 1 && availableCredits > 1) { // creditsNeeded >= availableCredits
            grantCredits = availableCredits - 1; // Keep 1 credit left for a simple request
        } else {
            grantCredits = 1;
        }
        packet.setCreditsAssigned(grantCredits);
        return grantCredits;
    }

    private void negotiateDialect() throws TransportException {
        logger.debug("Negotiating dialects {} with server {}", config.getSupportedDialects(), getRemoteHostname());
        SMB2Packet negotiatePacket = new SMB2NegotiateRequest(config.getSupportedDialects(), connectionInfo.getClientGuid(), config.isSigningRequired());
        Future<SMB2Packet> send = send(negotiatePacket);
        SMB2Packet negotiateResponse = Futures.get(send, getConfig().getTransactTimeout(), TimeUnit.MILLISECONDS, TransportException.Wrapper);
        if (!(negotiateResponse instanceof SMB2NegotiateResponse)) {
            throw new IllegalStateException("Expected a SMB2 NEGOTIATE Response, but got: " + negotiateResponse);
        }
        SMB2NegotiateResponse resp = (SMB2NegotiateResponse) negotiateResponse;
        connectionInfo.negotiated(resp);
        logger.debug("Negotiated the following connection settings: {}", connectionInfo);
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
        logger.debug("Server granted us {} credits for {}, now available: {} credits", packet.getHeader().getCreditResponse(), packet, connectionInfo.getSequenceWindow().available());

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

        if (packet.getHeader().getSessionId() != 0 && (packet.getHeader().getMessage() != SMB2MessageCommandCode.SMB2_SESSION_SETUP)) {
            Session session = connectionInfo.getSessionTable().find(packet.getHeader().getSessionId());
            if (session == null) {
                // check for a not-yet-authenticated session
                session = connectionInfo.getPreauthSessionTable().find(packet.getHeader().getSessionId());
                if (session == null) {
                    logger.warn("Illegal request, no session matching the sessionId: {}", packet.getHeader().getSessionId());
                    //TODO maybe tear down the connection?
                    return;
                }
            }

            // check packet signature.  Drop the packet if it is not correct.
            if (packet.getHeader().isFlagSet(SMB2MessageFlag.SMB2_FLAGS_SIGNED)) {
                if (!session.getPacketSignatory().verify(packet)) {
                    logger.warn("Invalid packet signature for packet {}", packet);
                    if (config.isSigningRequired()) {
                        throw new TransportException("Packet signature for packet " + packet + " was not correct");
                    }
                }
            } else if (config.isSigningRequired()) {
                logger.warn("Illegal request, client requires message signing, but the received message is not signed.");
                throw new TransportException("Client requires signing, but packet " + packet + " was not signed");
            }
        }

        // [MS-SMB2].pdf 3.2.5.1.8 Processing the Response
        connectionInfo.getOutstandingRequests().receivedResponseFor(messageId).getPromise().deliver(packet);
    }

    @Override
    public void handleError(Throwable t) {
        connectionInfo.getOutstandingRequests().handleError(t);
        try {
            this.close();
        } catch (Exception e) {
            String exceptionClass = e.getClass().getSimpleName();
            logger.debug("{} while closing connection on error, ignoring: {}", exceptionClass, e.getMessage());
        }
    }

    @Handler
    @SuppressWarnings("unused")
    private void sessionLogoff(SessionLoggedOff loggedOff) {
        connectionInfo.getSessionTable().sessionClosed(loggedOff.getSessionId());
        logger.debug("Session << {} >> logged off", loggedOff.getSessionId());
    }
}
