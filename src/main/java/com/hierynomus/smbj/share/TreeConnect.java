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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2ShareCapabilities;
import com.hierynomus.mssmb2.SMB2ShareFlags;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.mssmb2.messages.SMB2TreeDisconnect;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.ConnectionContext;
import com.hierynomus.smbj.connection.NegotiatedProtocol;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.event.TreeDisconnected;
import com.hierynomus.smbj.session.Session;

/**
 *
 */
public class TreeConnect {

    private long treeId;
    private SmbPath smbPath;
    private Session session;
    private final Set<SMB2ShareCapabilities> capabilities;
    private final NegotiatedProtocol negotiatedProtocol;
    private SmbConfig config;
    private final SMBEventBus bus;
    private final Set<AccessMask> maximalAccess;
    private final Set<SMB2ShareFlags> shareFlags;
    private final boolean encryptData;

    public TreeConnect(long treeId, SmbPath smbPath, Session session, Set<SMB2ShareCapabilities> capabilities, SmbConfig config, ConnectionContext connectionContext, SMBEventBus bus, Set<AccessMask> maximalAccess, Set<SMB2ShareFlags> shareFlags) {
        this.treeId = treeId;
        this.smbPath = smbPath;
        this.session = session;
        this.capabilities = capabilities;
        this.negotiatedProtocol = connectionContext.getNegotiatedProtocol();
        this.config = config;
        this.bus = bus;
        this.maximalAccess = maximalAccess;
        this.shareFlags = Collections.unmodifiableSet(new HashSet<>(shareFlags));
        this.encryptData = this.shareFlags.contains(SMB2ShareFlags.SMB2_SHAREFLAG_ENCRYPT_DATA) && negotiatedProtocol.getDialect().isSmb3x() && connectionContext.supportsEncryption();
    }

    void close() throws TransportException {
        try {
            try {
                checkEncryptionAvailable();
            } catch (SMBRuntimeException e) {
                throw new TransportException(e.getMessage(), e);
            }
            SMB2TreeDisconnect disconnect = new SMB2TreeDisconnect(negotiatedProtocol.getDialect(), session.getSessionId(), treeId);
            Future<SMB2Packet> send = isEncryptData() ? session.send(disconnect, true) : session.send(disconnect);
            SMB2Packet smb2Packet = Futures.get(send, config.getTransactTimeout(), TimeUnit.MILLISECONDS, TransportException.Wrapper);
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

    /**
     * Returns [MS-SMB2] TreeConnect.EncryptData: true when the TREE_CONNECT response set
     * SMB2_SHAREFLAG_ENCRYPT_DATA, the dialect is SMB 3.x and the connection supports encryption.
     *
     * @return whether this tree connect requires encryption on this connection
     */
    public boolean isEncryptData() {
        return encryptData;
    }

    /**
     * Returns an unmodifiable copy of the share flags returned by the server, including
     * SMB2_SHAREFLAG_ENCRYPT_DATA even when this connection cannot encrypt.
     *
     * @return the share flags from the TREE_CONNECT response
     */
    public Set<SMB2ShareFlags> getShareFlags() {
        return shareFlags;
    }

    void checkEncryptionAvailable() {
        if (shareFlags.contains(SMB2ShareFlags.SMB2_SHAREFLAG_ENCRYPT_DATA)
                && (!isEncryptData() || session.getSessionContext().getEncryptionKey() == null)) {
            throw new SMBRuntimeException("Share " + smbPath
                    + " requires encryption but encryption is not available on this connection");
        }
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

    public SmbConfig getConfig() {
        return config;
    }

    public NegotiatedProtocol getNegotiatedProtocol() {
        return negotiatedProtocol;
    }

    @Override
    public String toString() {
        return String.format("TreeConnect[%s](%s)", treeId, smbPath);
    }
}
