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
import com.hierynomus.mssmb2.messages.SMB2Logoff;
import com.hierynomus.mssmb2.messages.SMB2TreeConnectRequest;
import com.hierynomus.mssmb2.messages.SMB2TreeConnectResponse;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.event.SessionLoggedOff;
import com.hierynomus.smbj.event.TreeDisconnected;
import com.hierynomus.smbj.share.*;
import com.hierynomus.smbj.transport.TransportException;
import net.engio.mbassy.listener.Handler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.Future;

/**
 * A Session
 */
public class Session implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(Session.class);
    private long sessionId;

    private PacketSignatory packetSignatory;
    private boolean serverSigningRequired;

    private Connection connection;
    private SMBEventBus bus;
    private TreeConnectTable treeConnectTable = new TreeConnectTable();

    public Session(long sessionId, Connection connection, SMBEventBus bus, boolean signingRequired) {
        this.sessionId = sessionId;
        this.connection = connection;
        this.bus = bus;
        this.packetSignatory = new PacketSignatory(connection.getNegotiatedProtocol().getDialect());
        this.serverSigningRequired = signingRequired;
        if (bus != null) {
            bus.subscribe(this);
        }
    }

    public long getSessionId() {
        return sessionId;
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
        TreeConnect connectedConnect = treeConnectTable.getTreeConnect(shareName);
        if (connectedConnect != null) {
            logger.info("Returning cached Share {} for {}", connectedConnect.getTreeId(), shareName);
            return connectedConnect.getHandle();
        } else {
            return connectTree(shareName);
        }
    }

    private Share connectTree(final String shareName) {
        String remoteHostname = connection.getRemoteHostname();
        SmbPath smbPath = new SmbPath(remoteHostname, shareName);
        logger.info("Connection to {} on session {}", smbPath, sessionId);
        try {
            SMB2TreeConnectRequest smb2TreeConnectRequest = new SMB2TreeConnectRequest(connection.getNegotiatedProtocol().getDialect(), smbPath, sessionId);
            smb2TreeConnectRequest.getHeader().setCreditRequest(256);
            Future<SMB2TreeConnectResponse> send = this.send(smb2TreeConnectRequest);
            SMB2TreeConnectResponse response = Futures.get(send, TransportException.Wrapper);
            if (response.getHeader().getStatus().isError()) {
                logger.debug(response.getHeader().toString());
                throw new SMBApiException(response.getHeader(), "Could not connect to " + smbPath);
            }

            if (response.getCapabilities().contains(SMB2ShareCapabilities.SMB2_SHARE_CAP_ASYMMETRIC)) {
                throw new SMBRuntimeException("ASYMMETRIC capability unsupported");
            }

            long treeId = response.getHeader().getTreeId();
            TreeConnect treeConnect = new TreeConnect(treeId, smbPath, this, response.getCapabilities(), connection, bus);
            treeConnectTable.register(treeConnect);
            if (response.isDiskShare()) {
                return new DiskShare(smbPath, treeConnect);
            } else if (response.isNamedPipe()) {
                return new NamedPipe(smbPath, treeConnect);
            } else if (response.isPrinterShare()) {
                return new PrinterShare(smbPath, treeConnect);
            } else {
                throw new SMBRuntimeException("Unknown ShareType returned in the TREE_CONNECT Response");
            }
        } catch (TransportException e) {
            throw new SMBRuntimeException(e);
        }
    }

    @Handler
    private void disconnectTree(TreeDisconnected disconnectEvent) {
        if (disconnectEvent.getSessionId() == sessionId) {
            logger.debug("Notified of TreeDisconnected <<{}>>", disconnectEvent.getTreeId());
            treeConnectTable.closed(disconnectEvent.getTreeId());
        }
    }

    public void logoff() throws TransportException {
        logger.info("Logging off session {} from host {}", sessionId, connection.getRemoteHostname());
        for (TreeConnect treeConnect : treeConnectTable.getOpenTreeConnects()) {
            try {
                treeConnect.getHandle().close();
            } catch (IOException e) {
                logger.error("Caught exception while closing TreeConnect with id: {}", treeConnect.getTreeId(), e);
            }
        }
        SMB2Logoff logoff = new SMB2Logoff(connection.getNegotiatedProtocol().getDialect(), sessionId);
        SMB2Logoff response = Futures.get(this.<SMB2Logoff>send(logoff), TransportException.Wrapper);
        if (!response.getHeader().getStatus().isSuccess()) {
            throw new SMBApiException(response.getHeader(), "Could not logoff session <<" + sessionId + ">>");
        }
        bus.publish(new SessionLoggedOff(sessionId));
    }

    public boolean isSigningRequired() {
        return serverSigningRequired;
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
        if (serverSigningRequired && !packetSignatory.isInitialized()) {
            throw new TransportException("Message signing is required, but no signing key is negotiated");
        }
        return connection.send(packetSignatory.sign(packet));
    }

    public void setBus(SMBEventBus bus) {
        if (this.bus != null) {
            this.bus.unsubscribe(this);
            this.bus = null;
        }
        this.bus = bus;
        bus.subscribe(this);
    }

    public void setSessionId(long sessionId) {
        this.sessionId = sessionId;
    }

    public PacketSignatory getPacketSignatory() {
        return packetSignatory;
    }
}
