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

import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2ShareCapabilities;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.mssmb2.messages.*;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.event.SessionLoggedOff;
import com.hierynomus.smbj.event.TreeDisconnected;
import com.hierynomus.smbj.share.*;
import net.engio.mbassy.listener.Handler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * A Session
 */
public class Session implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(Session.class);
    private long sessionId;

    private PacketSignatory packetSignatory;
    private boolean signingRequired;
    private boolean encryptData; // SMB3.x

    private Connection connection;
    private SMBEventBus bus;
    private boolean dfsEnabled;
    private TreeConnectTable treeConnectTable = new TreeConnectTable();
    private AuthenticationContext userCredentials;

    private boolean guest;
    private boolean anonymous;

    public Session(Connection connection, AuthenticationContext userCredentials, SMBEventBus bus, boolean dfsEnabled, SecurityProvider securityProvider) {
        this.connection = connection;
        this.userCredentials = userCredentials;
        this.bus = bus;
        this.dfsEnabled = dfsEnabled;
        this.packetSignatory = new PacketSignatory(connection.getNegotiatedProtocol().getDialect(), securityProvider);
        if (bus != null) {
            bus.subscribe(this);
        }
    }

    public void init(SMB2SessionSetup setup) {
        this.guest = setup.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_GUEST);
        this.anonymous = setup.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_IS_NULL);
        validateAndSetSigning(setup);
        if (guest || anonymous) {
            packetSignatory.init(null); // De-initialize the signatory if it was initialized with a bogus key during the auth
        }
    }

    /**
     * [MS-SMB2] 3.2.5.3.1 Handling a New Authentication
     * @param setup
     */
    private void validateAndSetSigning(SMB2SessionSetup setup) {
        boolean requireMessageSigning = connection.getConfig().isSigningRequired();
        boolean connectionSigningRequired = connection.getConnectionInfo().isServerRequiresSigning();

        if (requireMessageSigning || connectionSigningRequired) {
            signingRequired = true;
        }

        if (anonymous) {
            // If the security subsystem indicates that the session was established by an anonymous user, Session.SigningRequired MUST be set to FALSE.
            signingRequired = false;
        }
        if (guest && connection.getConfig().isSigningRequired()) {
            throw new SMB2GuestSigningRequiredException();
        } else if (guest) {
            signingRequired = false;
        }
        if (connection.getNegotiatedProtocol().getDialect().isSmb3x() && setup.getSessionFlags().contains(SMB2SessionSetup.SMB2SessionFlags.SMB2_SESSION_FLAG_ENCRYPT_DATA)) {
            encryptData = true;
            signingRequired = false;
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
     * [MS-SMB2].pdf 3.2.4.2 Application Requests a Connection to a Share
     * [MS-SMB2].pdf 3.2.4.2.4 Connecting to the Share
     * [MS-SMB2].pdf 3.2.5.5 Receiving an SMB2 TREE_CONNECT Response
     *
     * @param shareName The name of the share to connect to.
     * @return the handle to the connected share.
     */
    public Share connectShare(String shareName) {
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
        SmbPath smbPath = new SmbPath(remoteHostname, shareName);
        logger.info("Connecting to {} on session {}", smbPath, sessionId);
        try {
            SMB2TreeConnectRequest smb2TreeConnectRequest = new SMB2TreeConnectRequest(connection.getNegotiatedProtocol().getDialect(), smbPath, sessionId);
            smb2TreeConnectRequest.getHeader().setCreditRequest(256);
            Future<SMB2TreeConnectResponse> send = this.send(smb2TreeConnectRequest);
            SMB2TreeConnectResponse response = Futures.get(send, connection.getConfig().getTransactTimeout(), TimeUnit.MILLISECONDS, TransportException.Wrapper);
            if (response.getHeader().getStatus().isError()) {
                logger.debug(response.getHeader().toString());
                throw new SMBApiException(response.getHeader(), "Could not connect to " + smbPath);
            }

            if (response.getCapabilities().contains(SMB2ShareCapabilities.SMB2_SHARE_CAP_ASYMMETRIC)) {
                throw new SMBRuntimeException("ASYMMETRIC capability unsupported");
            }

            long treeId = response.getHeader().getTreeId();
            TreeConnect treeConnect = new TreeConnect(treeId, smbPath, this, response.getCapabilities(), connection, bus);

            Share share;
            if (response.isDiskShare() && dfsEnabled && response.getCapabilities().contains(SMB2ShareCapabilities.SMB2_SHARE_CAP_DFS)) {
                share = new DFSDiskShare(smbPath, treeConnect);
            } else if (response.isDiskShare()) {
                share = new DiskShare(smbPath, treeConnect);
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
            SMB2Logoff logoff = new SMB2Logoff(connection.getNegotiatedProtocol().getDialect(), sessionId);
            SMB2Logoff response = Futures.get(this.<SMB2Logoff>send(logoff), connection.getConfig().getTransactTimeout(), TimeUnit.MILLISECONDS, TransportException.Wrapper);
            if (!response.getHeader().getStatus().isSuccess()) {
                throw new SMBApiException(response.getHeader(), "Could not logoff session <<" + sessionId + ">>");
            }
        } finally {
            bus.publish(new SessionLoggedOff(sessionId));
        }
    }

    public boolean isSigningRequired() {
        return signingRequired;
    }

    public boolean isGuest() {
        return guest;
    }

    public boolean isAnonymous() {
        return anonymous;
    }

    public void setSigningKey(byte[] signingKeyBytes) {
        packetSignatory.init(signingKeyBytes);
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
        if (signingRequired && !packetSignatory.isInitialized()) {
            throw new TransportException("Message signing is required, but no signing key is negotiated");
        }
        return connection.send(packetSignatory.sign(packet));
    }

    public <T extends SMB2Packet> T processSendResponse(SMB2CreateRequest packet) throws TransportException {
        Future<T> responseFuture = send(packet);
        return Futures.get(responseFuture, SMBRuntimeException.Wrapper);
    }

    public AuthenticationContext getAuthenticationContext() {
        return userCredentials;
    }

    public PacketSignatory getPacketSignatory() {
        return packetSignatory;
    }
}
