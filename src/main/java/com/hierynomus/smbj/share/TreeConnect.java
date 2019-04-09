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

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2ShareCapabilities;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.mssmb2.SMB2ShareFlags;
import com.hierynomus.mssmb2.messages.SMB2TreeDisconnect;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.event.TreeDisconnected;
import com.hierynomus.smbj.session.Session;

import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 *
 */
public class TreeConnect {

    private long treeId;
    private SmbPath smbPath;
    private Session session;
    private final Set<SMB2ShareFlags> shareFlags;
    private final Set<SMB2ShareCapabilities> capabilities;
    private Connection connection;
    private final SMBEventBus bus;
    private final Set<AccessMask> maximalAccess;
    private boolean encryptData; // SMB3.x

    @Deprecated
    public TreeConnect(long treeId, SmbPath smbPath, Session session, Set<SMB2ShareCapabilities> capabilities, Connection connection, SMBEventBus connectionPrivateBus, Set<AccessMask> maximalAccess) {
        this(treeId, smbPath, session, capabilities, connection, connectionPrivateBus, maximalAccess, EnumSet.noneOf(SMB2ShareFlags.class));
    }

    public TreeConnect(long treeId, SmbPath smbPath, Session session, Set<SMB2ShareCapabilities> capabilities, Connection connection, SMBEventBus bus, Set<AccessMask> maximalAccess, Set<SMB2ShareFlags> shareFlags) {
        this.treeId = treeId;
        this.smbPath = smbPath;
        this.session = session;
        this.shareFlags = shareFlags;
        this.capabilities = capabilities;
        this.connection = connection;
        this.bus = bus;
        this.maximalAccess = maximalAccess;
        // 3.2.5.5 Receiving an SMB2 TREE_CONNECT Response, TreeConnect.EncryptData
        if (connection.getNegotiatedProtocol().getDialect().isSmb3x()
            && connection.getConnectionInfo().isConnectionSupportEncrypt()
            && shareFlags.contains(SMB2ShareFlags.SMB2_SHAREFLAG_ENCRYPT_DATA)) {
            encryptData = true;
        }
    }

    Connection getConnection() {
        return connection;
    }

    void close() throws TransportException {
        try {
            SMB2TreeDisconnect disconnect = new SMB2TreeDisconnect(connection.getNegotiatedProtocol().getDialect(), session.getSessionId(), treeId);
            Future<SMB2Packet> send = sendBySession(disconnect);
            SMB2Packet smb2Packet = Futures.get(send, connection.getConfig().getTransactTimeout(), TimeUnit.MILLISECONDS, TransportException.Wrapper);
            if (!NtStatus.isSuccess(smb2Packet.getHeader().getStatusCode())) {
                throw new SMBApiException(smb2Packet.getHeader(), "Error closing connection to " + smbPath);
            }
        } finally {
            bus.publish(new TreeDisconnected(session.getSessionId(), treeId));
        }
    }

    public String getShareName() {
        return smbPath.getShareName();
    }

    public long getTreeId() {
        return treeId;
    }

    public Session getSession() {
        return session;
    }

    public Set<AccessMask> getMaximalAccess() {
        return maximalAccess;
    }

    public Set<SMB2ShareFlags> getShareFlags() {
        return shareFlags;
    }

    public boolean isDfsShare() {
        return capabilities.contains(SMB2ShareCapabilities.SMB2_SHARE_CAP_DFS);
    }

    public boolean isCAShare() {
        return capabilities.contains(SMB2ShareCapabilities.SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY);
    }

    public boolean isScaleoutShare() {
        return capabilities.contains(SMB2ShareCapabilities.SMB2_SHARE_CAP_SCALEOUT);
    }

    public boolean isEncryptData() {
        return encryptData;
    }

    /***
     * Send the packet by session with ensure the packet will correctly handle the encryption part if needed
     *
     * @param packet SMBPacket to send
     * @param <T> the response packet to the packet you send
     * @return a Future to be used to retrieve the response packet
     * @throws TransportException
     */
    private <T extends SMB2Packet> Future<T> sendBySession(SMB2Packet packet) throws TransportException {
        if (encryptData || session.isEncryptData() || connection.isClientDecidedEncrypt()) {
            packet.setRequireEncrypt(true);
        }
        return session.send(packet);
    }

    @Override
    public String toString() {
        return String.format("TreeConnect[%s](%s)", treeId, smbPath);
    }
}
