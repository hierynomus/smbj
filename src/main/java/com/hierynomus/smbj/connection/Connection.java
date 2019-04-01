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

import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb.SMB1PacketFactory;
import com.hierynomus.mssmb.SMB1NotSupportedException;
import com.hierynomus.mssmb.SMB1Packet;
import com.hierynomus.mssmb.messages.SMB1ComNegotiateRequest;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2CancelRequest;
import com.hierynomus.mssmb2.messages.SMB2NegotiateRequest;
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse;
import com.hierynomus.mssmb2.messages.SMB2SessionSetup;
import com.hierynomus.protocol.commons.Factory;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.concurrent.CancellableFuture;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.protocol.transport.*;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smb.SMBPacketData;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticateResponse;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.auth.Authenticator;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.event.ConnectionClosed;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.event.SessionLoggedOff;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.spnego.NegTokenInit;
import com.hierynomus.spnego.NegTokenInit2;
import com.hierynomus.spnego.SpnegoException;
import net.engio.mbassy.listener.Handler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import static com.hierynomus.mssmb2.SMB2Packet.SINGLE_CREDIT_PAYLOAD_SIZE;
import static com.hierynomus.mssmb2.messages.SMB2SessionSetup.SMB2SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED;
import static java.lang.String.format;

/**
 * A connection to a server.
 */
public class Connection implements Closeable, PacketReceiver<SMBPacketData<?>> {
    private static final Logger logger = LoggerFactory.getLogger(Connection.class);
    private static final DelegatingSMBMessageConverter converter = new DelegatingSMBMessageConverter(new SMB2PacketFactory(), new SMB1PacketFactory());

    private ConnectionInfo connectionInfo;
    private SessionTable sessionTable = new SessionTable();
    private SessionTable preauthSessionTable = new SessionTable();
    private OutstandingRequests outstandingRequests = new OutstandingRequests();
    private SequenceWindow sequenceWindow;
    private SMB2MessageConverter smb2Converter = new SMB2MessageConverter();

    private String remoteName;

    private SMBClient client;

    public SMBClient getClient() {
        return client;
    }

    private SmbConfig config;
    private TransportLayer<SMBPacket<?, ?>> transport;
    private final SMBEventBus bus;
    private final ReentrantLock lock = new ReentrantLock();
    private int remotePort;

    public Connection(SmbConfig config, SMBClient client, SMBEventBus bus) {
        this.config = config;
        this.client = client;
        this.transport = config.getTransportLayerFactory().createTransportLayer(new PacketHandlers<>(new SMBPacketSerializer(), this, converter), config);
        this.bus = bus;
        bus.subscribe(this);
    }

    public Connection(Connection connection) {
        this.client = connection.client;
        this.config = connection.config;
        this.transport = connection.transport;
        this.bus = connection.bus;
        bus.subscribe(this);
    }

    public void connect(String hostname, int port) throws IOException {
        if (isConnected()) {
            throw new IllegalStateException(format("This connection is already connected to %s", getRemoteHostname()));
        }
        this.remoteName = hostname;
        this.remotePort = port;
        transport.connect(new InetSocketAddress(hostname, port));
        this.sequenceWindow = new SequenceWindow();
        this.connectionInfo = new ConnectionInfo(config.getClientGuid(), hostname);
        negotiateDialect();
        logger.info("Successfully connected to: {}", getRemoteHostname());
    }

    @Override
    public void close() throws IOException {
        close(false);
    }

    /**
     * Close the Connection. If {@code force} is set to true, it forgoes the {@link Session#close()} operation on the open sessions, and it just
     * calls the {@link TransportLayer#disconnect()}.
     *
     * @param force if set, does not nicely terminate the open sessions.
     * @throws IOException If any error occurred during close-ing.
     */
    public void close(boolean force) throws IOException {
        try {
            if (!force) {
                for (Session session : sessionTable.activeSessions()) {
                    try {
                        session.close();
                    } catch (IOException e) {
                        logger.warn("Exception while closing session {}", session.getSessionId(), e);
                    }
                }
            }
        } finally {
            transport.disconnect();
            logger.info("Closed connection to {}", getRemoteHostname());
            bus.publish(new ConnectionClosed(remoteName, remotePort));
        }
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
            authenticator.init(config);
            Session session = getSession(authContext);
            byte[] securityContext = processAuthenticationToken(authenticator, authContext, connectionInfo.getGssNegotiateToken(), session);
            SMB2SessionSetup receive = initiateSessionSetup(securityContext, 0L);
            long preauthSessionId = receive.getHeader().getSessionId();
            if (preauthSessionId != 0L) {
                preauthSessionTable.registerSession(preauthSessionId, session);
            }
            try {
                while (receive.getHeader().getStatusCode() == NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue()) {
                    logger.debug("More processing required for authentication of {} using {}", authContext.getUsername(), authenticator);
                    securityContext = processAuthenticationToken(authenticator, authContext, receive.getSecurityBuffer(), session);
                    receive = initiateSessionSetup(securityContext, preauthSessionId);
                }

                if (receive.getHeader().getStatusCode() != NtStatus.STATUS_SUCCESS.getValue()) {
                    throw new SMBApiException(receive.getHeader(), format("Authentication failed for '%s' using %s", authContext.getUsername(), authenticator));
                }

                // Some devices only allocate the sessionId on the STATUS_SUCCESS message, not while authenticating.
                // So we need to set it on the session once we're completely authenticated.
                session.setSessionId(receive.getHeader().getSessionId());

                if (receive.getSecurityBuffer() != null) {
                    // process the last received buffer
                    processAuthenticationToken(authenticator, authContext, receive.getSecurityBuffer(), session);
                }
                session.init(receive);
                logger.info("Successfully authenticated {} on {}, session is {}", authContext.getUsername(), remoteName, session.getSessionId());
                sessionTable.registerSession(session.getSessionId(), session);
                return session;
            } finally {
                if (preauthSessionId != 0L) {
                    preauthSessionTable.sessionClosed(preauthSessionId);
                }
            }
        } catch (SpnegoException | IOException e) {
            throw new SMBRuntimeException(e);
        }
    }

    private Session getSession(AuthenticationContext authContext) {
        return new Session(this, authContext, bus, client.getPathResolver(), config.getSecurityProvider());
    }

    private byte[] processAuthenticationToken(Authenticator authenticator, AuthenticationContext authContext, byte[] inputToken, Session session) throws IOException {
        AuthenticateResponse resp = authenticator.authenticate(authContext, inputToken, session);
        if (resp == null) {
            return null;
        }
        connectionInfo.setWindowsVersion(resp.getWindowsVersion());
        connectionInfo.setNetBiosName(resp.getNetBiosName());
        byte[] securityContext = resp.getNegToken();
        if (resp.getSigningKey() != null) {
            session.setSigningKey(resp.getSigningKey());
        }
        return securityContext;
    }

    private SMB2SessionSetup initiateSessionSetup(byte[] securityContext, long sessionId) throws TransportException {
        SMB2SessionSetup req = new SMB2SessionSetup(
            connectionInfo.getNegotiatedProtocol().getDialect(),
            EnumSet.of(SMB2_NEGOTIATE_SIGNING_ENABLED),
            connectionInfo.getClientCapabilities());
        req.setSecurityBuffer(securityContext);
        req.getHeader().setSessionId(sessionId);
        return sendAndReceive(req);
    }

    private Authenticator getAuthenticator(AuthenticationContext context) throws SpnegoException {
        List<Factory.Named<Authenticator>> supportedAuthenticators = new ArrayList<>(config.getSupportedAuthenticators());
        List<ASN1ObjectIdentifier> mechTypes = new ArrayList<>();
        if (connectionInfo.getGssNegotiateToken().length > 0) {
            // The response NegTokenInit is a NegTokenInit2 according to MS-SPNG.
            NegTokenInit negTokenInit = new NegTokenInit2().read(connectionInfo.getGssNegotiateToken());
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
        Future<T> f = null;
        try {
            if (!(packet.getPacket() instanceof SMB2CancelRequest)) {
                int availableCredits = sequenceWindow.available();
                int grantCredits = calculateGrantedCredits(packet, availableCredits);
                if (availableCredits == 0) {
                    logger.warn(
                            "There are no credits left to send {}, will block until there are more credits available.",
                            packet.getHeader().getMessage());
                }
                long[] messageIds = sequenceWindow.get(grantCredits);
                packet.getHeader().setMessageId(messageIds[0]);
                logger.debug("Granted {} (out of {}) credits to {}", grantCredits, availableCredits, packet);
                packet.getHeader().setCreditRequest(Math
                        .max(SequenceWindow.PREFERRED_MINIMUM_CREDITS - availableCredits - grantCredits, grantCredits));

                Request request = new Request(packet.getPacket(), messageIds[0], UUID.randomUUID());
                outstandingRequests.registerOutstanding(request);
                f = request.getFuture(new CancelRequest(request, packet.getHeader().getSessionId()));
            }
            transport.write(packet);
            return f;
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
        SMB2Packet resp;
        if (config.isUseMultiProtocolNegotiate()) {
            resp = multiProtocolNegotiate();
        } else {
            resp = smb2OnlyNegotiate();
        }
        if (!(resp instanceof SMB2NegotiateResponse)) {
            throw new IllegalStateException("Expected a SMB2 NEGOTIATE Response, but got: " + resp);
        }
        SMB2NegotiateResponse negotiateResponse = (SMB2NegotiateResponse) resp;
        if (!NtStatus.isSuccess(negotiateResponse.getHeader().getStatusCode())) {
            throw new SMBApiException(negotiateResponse.getHeader(), "Failure during dialect negotiation");
        }
        connectionInfo.negotiated(negotiateResponse);
        logger.debug("Negotiated the following connection settings: {}", connectionInfo);
    }

    private SMB2Packet smb2OnlyNegotiate() throws TransportException {
        SMB2Packet negotiatePacket = new SMB2NegotiateRequest(config.getSupportedDialects(), connectionInfo.getClientGuid(), config.isSigningRequired());
        return sendAndReceive(negotiatePacket);
    }

    private SMB2Packet multiProtocolNegotiate() throws TransportException {
        SMB1Packet negotiatePacket = new SMB1ComNegotiateRequest(config.getSupportedDialects());
        long l = sequenceWindow.get();
        if (l != 0) {
            throw new IllegalStateException("The SMBv1 SMB_COM_NEGOTIATE packet needs to be the first packet sent.");
        }
        Request request = new Request(negotiatePacket, l, UUID.randomUUID());
        outstandingRequests.registerOutstanding(request);
        transport.write(negotiatePacket);
        Future<SMB2Packet> future = request.getFuture(null);
        SMB2Packet packet = Futures.get(future, getConfig().getTransactTimeout(), TimeUnit.MILLISECONDS, TransportException.Wrapper);
        if (!(packet instanceof SMB2NegotiateResponse)) {
            throw new IllegalStateException("Expected a SMB2 NEGOTIATE Response to our SMB_COM_NEGOTIATE, but got: " + packet);
        }
        SMB2NegotiateResponse negotiateResponse = (SMB2NegotiateResponse) packet;

        if (negotiateResponse.getDialect() == SMB2Dialect.SMB_2XX) {
            return smb2OnlyNegotiate();
        }
        return negotiateResponse;
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
    public void handle(SMBPacketData uncheckedPacket) throws TransportException {
        if (!(uncheckedPacket instanceof SMB2PacketData)) {
            throw new SMB1NotSupportedException();
        }

        SMB2PacketData packetData = (SMB2PacketData) uncheckedPacket;
        long messageId = packetData.getSequenceNumber();

        if (!outstandingRequests.isOutstanding(messageId)) {
            throw new TransportException("Received response with unknown sequence number <<" + messageId + ">>");
        }

        // [MS-SMB2].pdf 3.2.5.1.4 Granting Message Credits
        sequenceWindow.creditsGranted(packetData.getHeader().getCreditResponse());
        logger.debug("Server granted us {} credits for {}, now available: {} credits", packetData.getHeader().getCreditResponse(), packetData, sequenceWindow.available());

        Request request = outstandingRequests.getRequestByMessageId(messageId);
        logger.trace("Send/Recv of packet {} took << {} ms >>", packetData, System.currentTimeMillis() - request.getTimestamp().getTime());

        // [MS-SMB2].pdf 3.2.5.1.5 Handling Asynchronous Responses
        if (packetData.isIntermediateAsyncResponse()) {
            logger.debug("Received ASYNC packet {} with AsyncId << {} >>", packetData, packetData.getHeader().getAsyncId());
            request.setAsyncId(packetData.getHeader().getAsyncId());
            // TODO Expiration timer
            return;
        }

        // [MS-SMB2].pdf 3.2.5.1.6 Handling Session Expiration
        // if (packet.getHeader().getStatus() == NtStatus.STATUS_NETWORK_SESSION_EXPIRED) {
            // TODO reauthenticate session!
        // }

        SMB2Packet packet = null;
        try {
            packet = smb2Converter.readPacket(request.getPacket(), packetData);
        } catch (Buffer.BufferException e) {
            throw new TransportException("Unable to deserialize SMB2 Packet Data.", e);
        }
        long sessionId = packetData.getHeader().getSessionId();
        if (sessionId != 0L && (packetData.getHeader().getMessage() != SMB2MessageCommandCode.SMB2_SESSION_SETUP)) {
            Session session = sessionTable.find(sessionId);
            if (session == null) {
                // check for a not-yet-authenticated session
                session = preauthSessionTable.find(sessionId);
                if (session == null) {
                    logger.warn("Illegal request, no session matching the sessionId: {}", sessionId);
                    //TODO maybe tear down the connection?
                    return;
                }
            }


            // check packet signature. Drop the packet if it is not correct.
            verifyPacketSignature(packet, session);
        }

        // [MS-SMB2].pdf 3.2.5.1.8 Processing the Response
        outstandingRequests.receivedResponseFor(messageId).getPromise().deliver(packet);
    }

    private void verifyPacketSignature(SMB2Packet packet, Session session) throws TransportException {
        if (packet.getHeader().isFlagSet(SMB2MessageFlag.SMB2_FLAGS_SIGNED)) {
            if (!session.getPacketSignatory().verify(packet)) {
                logger.warn("Invalid packet signature for packet {}", packet);
                if (session.isSigningRequired()) {
                    throw new TransportException("Packet signature for packet " + packet + " was not correct");
                }
            }
        } else if (session.isSigningRequired()) {
            logger.warn("Illegal request, session requires message signing, but packet {} is not signed.", packet);
            throw new TransportException("Session requires signing, but packet " + packet + " was not signed");
        }
    }

    @Override
    public void handleError(Throwable t) {
        outstandingRequests.handleError(t);
        try {
            this.close();
        } catch (Exception e) {
            String exceptionClass = e.getClass().getSimpleName();
            logger.debug("{} while closing connection on error, ignoring: {}", exceptionClass, e.getMessage());
        }
    }

    public String getRemoteHostname() {
        return remoteName;
    }

    public boolean isConnected() {
        return transport.isConnected();
    }

    public ConnectionInfo getConnectionInfo() {
        return connectionInfo;
    }

    @Handler
    @SuppressWarnings("unused")
    private void sessionLogoff(SessionLoggedOff loggedOff) {
        sessionTable.sessionClosed(loggedOff.getSessionId());
        logger.debug("Session << {} >> logged off", loggedOff.getSessionId());
    }

    private static class DelegatingSMBMessageConverter implements PacketFactory<SMBPacketData<?>> {
        private PacketFactory<?>[] packetFactories;

        public DelegatingSMBMessageConverter(PacketFactory<?>... packetFactories) {
            this.packetFactories = packetFactories;
        }

        @Override
        public SMBPacketData<?> read(byte[] data) throws Buffer.BufferException, IOException {
            for (PacketFactory<?> packetFactory : packetFactories) {
                if (packetFactory.canHandle(data)) {
                    return (SMBPacketData<?>) packetFactory.read(data);
                }
            }
            throw new IOException("Unknown packet format received.");
        }

        @Override
        public boolean canHandle(byte[] data) {
            for (PacketFactory<?> packetFactory : packetFactories) {
                if (packetFactory.canHandle(data)) {
                    return true;
                }
            }
            return false;
        }
    }

    private class CancelRequest implements CancellableFuture.CancelCallback {
        private Request request;
        private long sessionId;

        public CancelRequest(Request request, long sessionId) {
            this.request = request;
            this.sessionId = sessionId;
        }

        /**
         * [MS-SMB2] 3.2.4.24 Application Requests Canceling an Operation
         */
        @Override
        public void cancel() {
            SMB2CancelRequest cancel = new SMB2CancelRequest(connectionInfo.getNegotiatedProtocol().getDialect(),
                request.getMessageId(),
                request.getAsyncId());
            try {
                sessionTable.find(sessionId).send(cancel);
                // transport.write(cancel);
            } catch (TransportException e) {
                logger.error("Failed to send {}", cancel);
            }
        }
    }
}
