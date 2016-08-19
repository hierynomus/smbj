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
package com.hierynomus.smbj.share;

import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2ShareCapabilities;
import com.hierynomus.mssmb2.messages.SMB2TreeDisconnect;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.event.TreeDisconnected;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.TransportException;

import java.util.EnumSet;
import java.util.concurrent.Future;

/**
 *
 */
public class TreeConnect {

    private long treeId;
    private SmbPath smbPath;
    private Session session;
    private final boolean isDfsShare;
    private final boolean isCAShare;
    private final boolean isScaleoutShare;
    private final EnumSet<SMB2ShareCapabilities> capabilities;
    private Connection connection;
    private final SMBEventBus bus;
    private Share handle;

    public TreeConnect(long treeId, SmbPath smbPath, Session session, EnumSet<SMB2ShareCapabilities> capabilities, Connection connection, SMBEventBus bus) {
        this.treeId = treeId;
        this.smbPath = smbPath;
        this.session = session;
        this.isDfsShare = capabilities.contains(SMB2ShareCapabilities.SMB2_SHARE_CAP_DFS);
        this.isCAShare = capabilities.contains(SMB2ShareCapabilities.SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY);
        this.isScaleoutShare = capabilities.contains(SMB2ShareCapabilities.SMB2_SHARE_CAP_SCALEOUT);
        this.capabilities = capabilities;
        this.connection = connection;
        this.bus = bus;
    }

    Connection getConnection() {
        return connection;
    }

    void close(Share share) throws TransportException {
        SMB2TreeDisconnect disconnect = new SMB2TreeDisconnect(connection.getNegotiatedProtocol().getDialect(), session.getSessionId(), treeId);
        Future<SMB2Packet> send = connection.send(disconnect);
        SMB2Packet smb2Packet = Futures.get(send, TransportException.Wrapper);
        if (!smb2Packet.getHeader().getStatus().isSuccess()) {
            throw new SMBApiException(smb2Packet.getHeader().getStatus(), "Error closing connection to " + smbPath);
        }
        share.disconnect();
        bus.publish(new TreeDisconnected(session.getSessionId(), treeId));
    }

    void setHandle(Share handle) {
        this.handle = handle;
    }

    public Share getHandle() {
        return handle;
    }

    public long getTreeId() {
        return treeId;
    }

    public Session getSession() {
        return session;
    }

    @Override
    public String toString() {
        return String.format("TreeConnect[%s](%s)", treeId, smbPath);
    }
}
