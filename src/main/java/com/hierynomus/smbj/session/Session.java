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
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.share.*;
import com.hierynomus.smbj.smb2.SMB2ShareCapabilities;
import com.hierynomus.smbj.smb2.messages.SMB2TreeConnectRequest;
import com.hierynomus.smbj.smb2.messages.SMB2TreeConnectResponse;
import com.hierynomus.smbj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;

/**
 * A Session
 */
public class Session {
    private static final Logger logger = LoggerFactory.getLogger(Session.class);
    long sessionId;
    private Connection connection;
    private Map<Long, TreeConnect> treeConnectTable = new ConcurrentHashMap<>();

    public Session(long sessionId, Connection connection) {
        this.sessionId = sessionId;
        this.connection = connection;
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
     * [MS-SMB2].pdf 3.2.4.2.4 Connecting to the Share
     * [MS-SMB2].pdf 3.2.5.5 Receiving an SMB2 TREE_CONNECT Response
     *
     * @param shareName The name of the share to connect to.
     * @return the handle to the connected share.
     */
    public Share connectShare(String shareName) {
        String remoteHostname = connection.getRemoteHostname();
        String smbPath = "\\\\" + remoteHostname + "\\" + shareName;
        logger.info("Connection to {} on session {}", smbPath, sessionId);
        try {
            Future<SMB2TreeConnectResponse> send = connection.send(new SMB2TreeConnectRequest(connection.getNegotiatedDialect(), smbPath, sessionId));
            SMB2TreeConnectResponse response = Futures.get(send, TransportException.Wrapper);
            if (response.getHeader().getStatus().isError()) {
                throw new SMBApiException(response.getHeader().getStatus(), "Could not connect to " + smbPath);
            }

            if (response.getCapabilities().contains(SMB2ShareCapabilities.SMB2_SHARE_CAP_ASYMMETRIC)) {
                throw new SMBRuntimeException("ASYMMETRIC capability unsupported");
            }

            long treeId = response.getHeader().getTreeId();
            TreeConnect treeConnect = new TreeConnect(treeId, this, response.getCapabilities());
            treeConnectTable.put(treeId, treeConnect);
            if (response.isDiskShare()) {
                return new DiskShare(treeConnect);
            } else if (response.isNamedPipe()) {
                return new NamedPipe(treeConnect);
            } else if (response.isPrinterShare()) {
                return new PrinterShare(treeConnect);
            } else {
                throw new SMBRuntimeException("Unknown ShareType returned in the TREE_CONNECT Response");
            }
        } catch (TransportException e) {
            throw new SMBRuntimeException(e);
        }
    }
}
