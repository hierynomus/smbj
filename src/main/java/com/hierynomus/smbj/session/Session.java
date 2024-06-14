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
package com.hierynomus.smbj.session;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2CreateRequest;
import com.hierynomus.mssmb2.messages.SMB2Logoff;
import com.hierynomus.mssmb2.messages.SMB2TreeConnectRequest;
import com.hierynomus.mssmb2.messages.SMB2TreeConnectResponse;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.connection.ConnectionContext;
import com.hierynomus.smbj.connection.PacketEncryptor;
import com.hierynomus.smbj.connection.PacketSignatory;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.event.SessionLoggedOff;
import com.hierynomus.smbj.event.TreeDisconnected;
import com.hierynomus.smbj.paths.PathResolveException;
import com.hierynomus.smbj.paths.PathResolver;
import com.hierynomus.smbj.share.*;
import net.engio.mbassy.listener.Handler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static java.lang.String.format;

/**
 * A Session
 */
public class Session implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(Session.class);
    private long sessionId;

    private Connection connection;
    private final SmbConfig config;
    private SMBEventBus bus;
    private final PathResolver pathResolver;
    private PacketSignatory signatory;
    private PacketEncryptor encryptor;
    private TreeConnectTable treeConnectTable = new TreeConnectTable();
    private Map<String, Session> nestedSessionsByHost = new HashMap<>();
    private ReentrantReadWriteLock nestedSessionsRwLock = new ReentrantReadWriteLock();
    private AuthenticationContext userCredentials;
    private SessionContext sessionContext;

    public Session(Connection connection, SmbConfig config, AuthenticationContext userCredentials, SMBEventBus bus, PathResolver pathResolver, PacketSignatory signatory, PacketEncryptor encryptor) {
        this.connection = connection;
        this.config = config;
        this.userCredentials = userCredentials;
        this.bus = bus;
        this.pathResolver = pathResolver;
        this.signatory = signatory;
        this.sessionContext = new SessionContext();
        this.encryptor = encryptor;
        if (bus != null) {
            bus.subscribe(this);
        }
    }

    public long getSessionId() {
        return sessionId;
    }

    public void setSessionId(long sessionId) {
        this.sessionId = sessionId;
    }

    /**
     * Connect to a share on the remote machine over the authenticated session.
     * <p/>
     * [MS-SMB2] 3.2.4.2 Application Requests a Connection to a Share
     * [MS-SMB2] 3.2.4.2.4 Connecting to the Share
     * [MS-SMB2] 3.2.5.5 Receiving an SMB2 TREE_CONNECT Response
     *
     * @param shareName The name of the share to connect to.
     * @return the handle to the connected share.
     */
    public Share connectShare(String shareName) {
        if (shareName.contains("\\")) {
            throw new IllegalArgumentException(format("Share name (%s) cannot contain '\\' characters.", shareName));
        }
        Share connectedShare = treeConnectTable.getTreeConnect(shareName);
        if (connectedShare != null) {
            logger.debug("Returning cached Share {} for {}", connectedShare, shareName);
            return connectedShare;
        } else {
            return connectTree(shareName);
        }
    }

    private Share connectTree(final String shareName) {
        String remoteHostname = connection.getRemoteHostname();
        final SmbPath smbPath = new SmbPath(remoteHostname, shareName);
        logger.info("Connecting to {} on session {}", smbPath, sessionId);
        try {
            SMB2TreeConnectRequest smb2TreeConnectRequest = new SMB2TreeConnectRequest(connection.getNegotiatedProtocol().getDialect(), smbPath, sessionId);
            smb2TreeConnectRequest.getHeader().setCreditRequest(256);
            Future<SMB2TreeConnectResponse> send = this.send(smb2TreeConnectRequest);
            SMB2TreeConnectResponse response = Futures.get(send, config.getTransactTimeout(), TimeUnit.MILLISECONDS, TransportException.Wrapper);
            try {
                Share share = pathResolver.resolve(this, response, smbPath, new PathResolver.ResolveAction<Share>() {
                    @Override
                    public Share apply(SmbPath target) {
                        Session session = Session.this;
                        if (!target.isOnSameHost(smbPath)) {
                            logger.info("Re-routing the connection to host {}", target.getHostname());
                            session = getNestedSession(target);
                        }
                        if (!target.isOnSameShare(smbPath)) {
                            return session.connectShare(target.getShareName());
                        }
                        return null;
                    }
                });

                if (share != null) {
                    return share;
                }
            } catch (PathResolveException ignored) {
                // Ignored
            }

            if (NtStatus.isError(response.getHeader().getStatusCode())) {
                logger.debug(response.getHeader().toString());
                throw new SMBApiException(response.getHeader(), "Could not connect to " + smbPath);
            }

            if (response.getCapabilities().contains(SMB2ShareCapabilities.SMB2_SHARE_CAP_ASYMMETRIC)) {
                throw new SMBRuntimeException("ASYMMETRIC capability unsupported");
            }

            long treeId = response.getHeader().getTreeId();
            TreeConnect treeConnect = new TreeConnect(treeId, smbPath, this, response.getCapabilities(), config, connection.getConnectionContext(), bus, response.getMaximalAccess(), response.getShareFlags());

            Share share;
            if (response.isDiskShare()) {
                share = new DiskShare(smbPath, treeConnect, pathResolver);
            } else if (response.isNamedPipe()) {
                share = new PipeShare(smbPath, treeConnect);
            } else if (response.isPrinterShare()) {
                share = new PrinterShare(smbPath, treeConnect);
            } else {
                throw new SMBRuntimeException("Unknown ShareType returned in the TREE_CONNECT Response");
            }

            treeConnectTable.register(share);
            return share;
        } catch (TransportException e) {
            throw new SMBRuntimeException(e);
        }
    }

    public Session getNestedSession(SmbPath resolvedSharePath) {
        nestedSessionsRwLock.readLock().lock();
        try {
            final Session existingSession = nestedSessionsByHost.get(resolvedSharePath.getHostname());
            if (existingSession != null) {
                return existingSession;
            }
        } finally {
            nestedSessionsRwLock.readLock().unlock();
        }

        Session session;
        nestedSessionsRwLock.writeLock().lock(); // update to write lock
        try {
            // re-check if other thread created the missing session in the meantime
            session = nestedSessionsByHost.get(resolvedSharePath.getHostname());

            if (session == null) {
                session = createNestedSession(resolvedSharePath);
                nestedSessionsByHost.put(resolvedSharePath.getHostname(), session);
            }
            nestedSessionsRwLock.readLock().lock();
        } finally {
            nestedSessionsRwLock.writeLock().unlock();
        }

        try {
            return session;
        } finally {
            nestedSessionsRwLock.readLock().unlock();
        }
    }

    private Session createNestedSession(SmbPath smbPath) {
        try {
            Connection connection = getConnection().getClient().connect(smbPath.getHostname());
            return connection.authenticate(getAuthenticationContext());
        } catch (IOException e) {
            throw new SMBApiException(NtStatus.STATUS_OTHER.getValue(), SMB2MessageCommandCode.SMB2_NEGOTIATE,
                "Could not connect to DFS root " + smbPath, e);
        }
    }

    @Handler
    @SuppressWarnings("unused")
    private void disconnectTree(TreeDisconnected disconnectEvent) {
        if (disconnectEvent.getSessionId() == sessionId) {
            logger.debug("Notified of TreeDisconnected <<{}>>", disconnectEvent.getTreeId());
            treeConnectTable.closed(disconnectEvent.getTreeId());
        }
    }

    public void logoff() throws TransportException {
        try {
            logger.info("Logging off session {} from host {}", sessionId, connection.getRemoteHostname());
            for (Share share : treeConnectTable.getOpenTreeConnects()) {
                try {
                    share.close();
                } catch (IOException e) {
                    logger.error("Caught exception while closing TreeConnect with id: {}", share.getTreeConnect().getTreeId(), e);
                }
            }

            nestedSessionsRwLock.writeLock().lock();
            try {
                for (Session nestedSession : nestedSessionsByHost.values()) {
                    logger.info("Logging off nested session {} for session {}", nestedSession.getSessionId(), sessionId);
                    try {
                        nestedSession.logoff();
                    } catch (TransportException te) {
                        logger.error("Caught exception while logging off nested session {}", nestedSession.getSessionId());
                    }
                }
            } finally {
                nestedSessionsRwLock.writeLock().unlock();
            }
            SMB2Logoff logoff = new SMB2Logoff(connection.getNegotiatedProtocol().getDialect(), sessionId);
            SMB2Logoff response = Futures.get(this.<SMB2Logoff>send(logoff), config.getTransactTimeout(), TimeUnit.MILLISECONDS, TransportException.Wrapper);
            if (!NtStatus.isSuccess(response.getHeader().getStatusCode())) {
                throw new SMBApiException(response.getHeader(), "Could not logoff session <<" + sessionId + ">>");
            }
        } finally {
            bus.publish(new SessionLoggedOff(sessionId));
        }
    }

    public boolean isSigningRequired() {
        return sessionContext.isSigningRequired();
    }

    public boolean isGuest() {
        return sessionContext.isGuest();
    }

    public boolean isAnonymous() {
        return sessionContext.isAnonymous();
    }

    @Override
    public void close() throws IOException {
        logoff();
    }

    public Connection getConnection() {
        return connection;
    }

    /**
     * send a packet.  The packet will be signed or not depending on the session's flags.
     *
     * @param packet SMBPacket to send
     * @return a Future to be used to retrieve the response packet
     * @throws TransportException
     */
    public <T extends SMB2Packet> Future<T> send(SMB2Packet packet) throws TransportException {

        if (shouldEncryptData()) {
            return connection.send(encryptor.encrypt(packet, sessionContext.getEncryptionKey()));
        }

        ConnectionContext connectionContext = connection.getConnectionContext();
        SMB2Dialect dialect = connection.getNegotiatedProtocol().getDialect();
        /*
         * Ref: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/973630a8-8aa1-4398-89a8-13cf830f194d
         * The client MUST sign the message if one of the following conditions is TRUE:
         * If Connection.Dialect is equal to "2.0.2" or "2.1", the message being sent contains a nonzero value in the
         * SessionId field and the session identified by the SessionId has Session.SigningRequired equal to TRUE.
         *
         * If Connection.Dialect belongs to 3.x dialect family, the message being sent contains a nonzero value in the
         * SessionId field and one of the following conditions is TRUE:
         *  - The session identified by SessionId has Session.EncryptData equal to FALSE.
         *  -  The tree connection identified by the TreeId field has TreeConnect.EncryptData equal to FALSE.
         * If Session.SigningRequired is FALSE, the client MAY<102> sign the request.
         */
        if (isSmb2(dialect) && (!connectionContext.isServerRequiresSigning() && !sessionContext.isSigningRequired())) {
            // send unsigned packets for smb2 only
            return connection.send(packet);
        }

        SecretKey signingKey = getSigningKey(packet.getHeader(), true);
        if (signingKey == null) {
            throw new TransportException("Message signing is required, but no signing key is negotiated");
        }

        return connection.send(signatory.sign(packet, signingKey));
    }

    private boolean isSmb2(SMB2Dialect dialect) {
        if (dialect == SMB2Dialect.SMB_2_0_2 || dialect == SMB2Dialect.SMB_2_1 || dialect == SMB2Dialect.SMB_2XX)
            return true;

        return false;
    }

    public <T extends SMB2Packet> T processSendResponse(SMB2CreateRequest packet) throws TransportException {
        Future<T> responseFuture = send(packet);
        return Futures.get(responseFuture, SMBRuntimeException.Wrapper);
    }

    /**
     * If Connection.Dialect belongs to the SMB 3.x dialect family, and the received message is an SMB2 SESSION_SETUP
     * Response without a status code equal to STATUS_SUCCESS in the header, the client MUST verify the signature of
     * the message as specified in section 3.1.5.1, using Session.SigningKey as the signing key, and passing the
     * response message.
     * For all other messages, the client MUST look up the Channel in Session.ChannelList, where the Channel.Connection
     * matches the connection on which this message is received, and MUST use Channel.SigningKey for verifying the
     * signature as specified in section 3.1.5.1.
     *
     *  Otherwise, the client MUST verify the signature of the message as specified in section 3.1.5.1,
     * using Session.SessionKey as the signing key, and passing the response message.
     *
     *
     * @param signing If true, check for signing mode, else get for verification mode
     * @return
     */
    public SecretKey getSigningKey(SMB2PacketHeader header, boolean signing) {
        if (connection.getNegotiatedProtocol().getDialect().isSmb3x()) {
            if (header.getMessage() == SMB2MessageCommandCode.SMB2_SESSION_SETUP) {
                if (signing) {
                    return sessionContext.getSigningKey();
                }
                if (header.getStatusCode() != NtStatus.STATUS_SUCCESS.getValue()) {
                    return sessionContext.getSigningKey();
                }
            }
            return sessionContext.getSigningKey(); // TODO channel.getSigningKey()
        }

        return sessionContext.getSessionKey();
    }

    /**
     * Returns whether packets for this session should be encrypted.
     *
     * @return
     * @throws TransportException When encryption is required and encryption key is missing.
     */
    public boolean shouldEncryptData() throws TransportException {
        if (sessionContext.isEncryptData() && sessionContext.getEncryptionKey() == null) {
            throw new TransportException("Message encryption is required, but no encryption key is negotiated");
        }

        boolean encryptData = sessionContext.isEncryptData();
        encryptData |= (sessionContext.getEncryptionKey() != null && connection.getConnectionContext().clientPrefersEncryption());

        return encryptData;
    }

    public SessionContext getSessionContext() {
        return sessionContext;
    }

    public AuthenticationContext getAuthenticationContext() {
        return userCredentials;
    }
}
