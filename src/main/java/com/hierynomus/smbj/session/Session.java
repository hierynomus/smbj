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

import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.event.SessionLoggedOff;
import com.hierynomus.smbj.event.TreeDisconnected;
import com.hierynomus.smbj.share.*;
import com.hierynomus.smbj.smb2.SMB2Packet;
import com.hierynomus.smbj.smb2.SMB2ShareCapabilities;
import com.hierynomus.smbj.smb2.messages.SMB2Logoff;
import com.hierynomus.smbj.smb2.messages.SMB2TreeConnectRequest;
import com.hierynomus.smbj.smb2.messages.SMB2TreeConnectResponse;
import com.hierynomus.smbj.transport.TransportException;
import net.engio.mbassy.listener.Filter;
import net.engio.mbassy.listener.Handler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;

/**
 * A Session
 */
public class Session implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(Session.class);
    long sessionId;
    private Connection connection;
    private SMBEventBus bus;
    private Map<Long, TreeConnect> treeConnectTable = new ConcurrentHashMap<>();

    public Session(long sessionId, Connection connection, SMBEventBus bus) {
        this.sessionId = sessionId;
        this.connection = connection;
        this.bus = bus;
        bus.subscribe(this);
    }

    public long getSessionId() {
        return sessionId;
    }

    /**
     * Connect to a share on the remote machine over the authenticated session.
     * <p/>
     * [MS-SMB2].pdf 3.2.4.2.4 Connecting to the Share
     * [MS-SMB2].pdf 3.2.5.5 Receiving an SMB2 TREE_CONNECT Response
     *
     * @param shareName The name of the share to connect to.
     * @return the handle to the connected share.
     */
    public Share connectShare(String shareName) {
        String remoteHostname = connection.getRemoteHostname();
        SmbPath smbPath = new SmbPath(remoteHostname, shareName);
        logger.info("Connection to {} on session {}", smbPath, sessionId);
        try {
            SMB2TreeConnectRequest smb2TreeConnectRequest = new SMB2TreeConnectRequest(connection
                    .getNegotiatedDialect(), smbPath, sessionId);
            smb2TreeConnectRequest.getHeader().setCreditRequest(256);
            Future<SMB2TreeConnectResponse> send = connection.send(smb2TreeConnectRequest);
            SMB2TreeConnectResponse response = Futures.get(send, TransportException.Wrapper);
            if (response.getHeader().getStatus().isError()) {
                throw new SMBApiException(response.getHeader().getStatus(), "Could not connect to " + smbPath);
            }

            if (response.getCapabilities().contains(SMB2ShareCapabilities.SMB2_SHARE_CAP_ASYMMETRIC)) {
                throw new SMBRuntimeException("ASYMMETRIC capability unsupported");
            }

            long treeId = response.getHeader().getTreeId();
            TreeConnect treeConnect = new TreeConnect(treeId, smbPath, this, response.getCapabilities(), connection, bus);
            treeConnectTable.put(treeId, treeConnect);
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
            logger.debug("Notified of TreeDisconnected <<" + disconnectEvent.getTreeId() + ">>");
            treeConnectTable.remove(disconnectEvent.getTreeId());
        }
    }

    public void logoff() throws TransportException {
        logger.info("Logging off session " + sessionId + " from host " + connection.getRemoteHostname());
        for (TreeConnect treeConnect : new ArrayList<>(treeConnectTable.values())) {
            try {
                treeConnect.getHandle().close();
            } catch (IOException e) {
                // TODO
            }
        }
        SMB2Logoff logoff = new SMB2Logoff(connection.getNegotiatedDialect(), sessionId);
        SMB2Logoff response = Futures.get(connection.<SMB2Logoff>send(logoff), TransportException.Wrapper);
        if (!response.getHeader().getStatus().isSuccess()) {
            throw new SMBApiException(response.getHeader().getStatus(), "Could not logoff session <<" + sessionId + ">>");
        }
        bus.publish(new SessionLoggedOff(sessionId));
    }


    @Override
    public void close() throws IOException {
        logoff();
    }

    public Connection getConnection() {
        return connection;
    }
}
