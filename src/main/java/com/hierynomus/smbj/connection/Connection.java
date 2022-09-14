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

import static com.hierynomus.mssmb2.SMB2Packet.SINGLE_CREDIT_PAYLOAD_SIZE;
import static java.lang.String.format;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.UUID;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import com.hierynomus.mssmb.SMB1PacketFactory;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2Cancel;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.concurrent.CancellableFuture;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.protocol.transport.PacketFactory;
import com.hierynomus.protocol.transport.PacketHandlers;
import com.hierynomus.protocol.transport.PacketReceiver;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smb.SMBPacketData;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.Pooled;
import com.hierynomus.smbj.connection.packet.DeadLetterPacketHandler;
import com.hierynomus.smbj.connection.packet.IncomingPacketHandler;
import com.hierynomus.smbj.connection.packet.SMB1PacketHandler;
import com.hierynomus.smbj.connection.packet.SMB2AsyncResponsePacketHandler;
import com.hierynomus.smbj.connection.packet.SMB2CompoundedPacketHandler;
import com.hierynomus.smbj.connection.packet.SMB2CreditGrantingPacketHandler;
import com.hierynomus.smbj.connection.packet.SMB2IsOutstandingPacketHandler;
import com.hierynomus.smbj.connection.packet.SMB2ProcessResponsePacketHandler;
import com.hierynomus.smbj.connection.packet.SMB2SignatureVerificationPacketHandler;
import com.hierynomus.smbj.connection.packet.SMB3DecryptingPacketHandler;
import com.hierynomus.smbj.event.ConnectionClosed;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.event.SessionLoggedOff;
import com.hierynomus.smbj.paths.DFSPathResolver;
import com.hierynomus.smbj.paths.PathResolver;
import com.hierynomus.smbj.paths.SymlinkPathResolver;
import com.hierynomus.smbj.server.ServerList;
import com.hierynomus.smbj.session.Session;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.engio.mbassy.listener.Handler;

/**
 * A connection to a server.
 */
public class Connection extends Pooled<Connection> implements Closeable, PacketReceiver<SMBPacketData<?>> {
    private static final Logger logger = LoggerFactory.getLogger(Connection.class);
    private static final DelegatingSMBMessageConverter converter = new DelegatingSMBMessageConverter(new SMB3EncryptedPacketFactory(), new SMB3CompressedPacketFactory(), new SMB2PacketFactory(), new SMB1PacketFactory());
    private IncomingPacketHandler packetHandlerChain;

    private ConnectionContext connectionContext;
    private SessionTable sessionTable = new SessionTable();
    private SessionTable preauthSessionTable = new SessionTable();
    OutstandingRequests outstandingRequests = new OutstandingRequests();
    SequenceWindow sequenceWindow;
    private SMB2MessageConverter smb2Converter = new SMB2MessageConverter();
    private PathResolver pathResolver;

    private final SMBClient client;
    final ServerList serverList;

    private PacketSignatory signatory;
    private PacketEncryptor encryptor;

    public SMBClient getClient() {
        return client;
    }

    private SmbConfig config;
    TransportLayer<SMBPacket<?, ?>> transport;
    private final SMBEventBus bus;
    private final ReentrantLock lock = new ReentrantLock();

    public Connection(SmbConfig config, SMBClient client, SMBEventBus bus, ServerList serverList) {
        this.config = config;
        this.client = client;
        this.transport = config.getTransportLayerFactory().createTransportLayer(new PacketHandlers<>(new SMBPacketSerializer(), this, converter), config);
        this.bus = bus;
        this.serverList = serverList;
        init();
    }

    private void init() {
        bus.subscribe(this);
        this.sequenceWindow = new SequenceWindow();
        this.signatory = new PacketSignatory(config.getSecurityProvider());
        this.encryptor = new PacketEncryptor(config.getSecurityProvider());

        this.packetHandlerChain = new SMB3DecryptingPacketHandler(sessionTable, encryptor).setNext(
            new SMB2CompoundedPacketHandler().setNext(
                new SMB2IsOutstandingPacketHandler(outstandingRequests).setNext(
                    new SMB2SignatureVerificationPacketHandler(sessionTable, signatory).setNext(
                        new SMB2CreditGrantingPacketHandler(sequenceWindow).setNext(
                            new SMB2AsyncResponsePacketHandler(outstandingRequests).setNext(
                                new SMB2ProcessResponsePacketHandler(smb2Converter, outstandingRequests).setNext(
                                    new SMB1PacketHandler().setNext(new DeadLetterPacketHandler()))))))));
    }

    public Connection(Connection connection) {
        this.client = connection.client;
        this.config = connection.config;
        this.transport = connection.transport;
        this.bus = connection.bus;
        this.serverList = connection.serverList;
        init();
    }

    public void connect(String hostname, int port) throws IOException {
        if (isConnected()) {
            throw new IllegalStateException(format("This connection is already connected to %s", getRemoteHostname()));
        }
        transport.connect(new InetSocketAddress(hostname, port));
        this.connectionContext = new ConnectionContext(config.getClientGuid(), hostname, port, config);
        new SMBProtocolNegotiator(this, config, connectionContext).negotiateDialect();
        this.signatory.init();
        this.encryptor.init(connectionContext);

        this.pathResolver = new SymlinkPathResolver(PathResolver.LOCAL);
        if (config.isDfsEnabled() && connectionContext.supportsDFS()) {
            this.pathResolver = new DFSPathResolver(pathResolver, config.getTransactTimeout());
        }

        logger.info("Successfully connected to: {}", getRemoteHostname());
    }

    @Override
    public void close() throws IOException {
        close(false);
    }

    /**
     * Close the Connection. If {@code force} is set to true, it forgoes the
     * {@link Session#close()} operation on the open sessions, and it just calls the
     * {@link TransportLayer#disconnect()}.
     *
     * <p>
     * If {@code force} is set to false, the usage counter of the connection reduces with one. If the usage count drops to zero the connection will be closed.
     * </p>
     *
     * @param force if set, does not nicely terminate the open sessions.
     * @throws IOException If any error occurred during close-ing.
     */
    public void close(boolean force) throws IOException {
        if (!force && !release()) {
            return;
        }
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
            bus.publish(new ConnectionClosed(connectionContext.getServer().getServerName(), connectionContext.getServer().getPort()));
        }
    }

    /**
     * Authenticate the user on this connection in order to start a (new) session.
     *
     * @return a (new) Session that is authenticated for the user.
     */
    public Session authenticate(AuthenticationContext authContext) {
        return new SMBSessionBuilder(this, config, new SMBSessionBuilder.SessionFactory() {
            @Override
            public Session createSession(AuthenticationContext context) {
                return new Session(Connection.this, config, context, bus, pathResolver, signatory, encryptor);
            }
        }).establish(authContext);
    }

    /**
     * send a packet.
     *
     * @param packet SMBPacket to send
     * @return a Future to be used to retrieve the response packet
     * @throws TransportException When a transport level error occurred
     */
    public <T extends SMB2Packet> Future<T> send(SMB2Packet packet) throws TransportException {
        Future<T> f = null;
        if (!(packet.getPacket() instanceof SMB2Cancel)) {
            // Need to lock around the sequence window calls to ensure no credits get stolen by another thread
            lock.lock();
            try {
                int availableCredits = sequenceWindow.available();
                int grantCredits = calculateGrantedCredits(packet, availableCredits);
                if (availableCredits == 0) {
                    logger.warn(
                        "There are no credits left to send {}, will block until there are more credits available.",
                        packet.getHeader().getMessage());
                }
                long[] messageIds = sequenceWindow.get(grantCredits);
                packet.getHeader().setMessageId(messageIds[0]);
                packet.getHeader().setCreditRequest(Math.max(SequenceWindow.PREFERRED_MINIMUM_CREDITS - availableCredits - grantCredits,
                        grantCredits));
                logger.debug("Granted {} (out of {}) credits to {}", grantCredits, availableCredits, packet);
            } finally {
                lock.unlock();
            }

            Request request = new Request(packet.getPacket(), packet.getHeader().getMessageId(), UUID.randomUUID());
            outstandingRequests.registerOutstanding(request);
            f = request.getFuture(new CancelRequest(request, packet.getHeader().getSessionId()));
        }
        transport.write(packet);
        return f;
    }

    <T extends SMB2Packet> T sendAndReceive(SMB2Packet packet) throws TransportException {
        return Futures.get(this.<T>send(packet), config.getTransactTimeout(), TimeUnit.MILLISECONDS, TransportException.Wrapper);
    }

    private int calculateGrantedCredits(final SMB2Packet packet, final int availableCredits) {
        final int grantCredits;
        int maxPayloadSize = packet.getMaxPayloadSize();
        int creditsNeeded = creditsNeeded(maxPayloadSize);
        if (creditsNeeded > 1 && !connectionContext.supportsMultiCredit()) {
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

    /**
     * [MS-SMB2] 3.1.5.2 Calculating the CreditCharge
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
        return connectionContext.getNegotiatedProtocol();
    }

    @Override
    public void handle(SMBPacketData<?> uncheckedPacket) throws TransportException {
        this.packetHandlerChain.handle(uncheckedPacket);
        // [MS-SMB2] 3.2.5.1.6 Handling Session Expiration
        // if (packet.getHeader().getStatus() == NtStatus.STATUS_NETWORK_SESSION_EXPIRED) {
        // TODO reauthenticate session!
        // }

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
        return connectionContext.getServer().getServerName();
    }

    public boolean isConnected() {
        return transport.isConnected();
    }

    public ConnectionContext getConnectionContext() {
        return connectionContext;
    }

    @Handler
    @SuppressWarnings("unused")
    private void sessionLogoff(SessionLoggedOff loggedOff) {
        sessionTable.removeSession(loggedOff.getSessionId());
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
            SMB2Cancel cancel = new SMB2Cancel(connectionContext.getNegotiatedProtocol().getDialect(),
                sessionId,
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

    SessionTable getSessionTable() {
        return sessionTable;
    }

    SessionTable getPreauthSessionTable() {
        return preauthSessionTable;
    }
}
