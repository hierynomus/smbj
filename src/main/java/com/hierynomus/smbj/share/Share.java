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

import java.io.IOException;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

import com.hierynomus.msdtyp.SecurityInformation;
import com.hierynomus.msfscc.FileInformationClass;
import com.hierynomus.msfscc.FileSystemInformationClass;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.TransportException;

public class Share implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(Share.class);
    private static final EnumSet<NtStatus> SUCCESS = EnumSet.of(NtStatus.STATUS_SUCCESS);
    private static final EnumSet<NtStatus> SUCCESS_OR_NO_MORE_FILES = EnumSet.of(NtStatus.STATUS_SUCCESS, NtStatus.STATUS_NO_MORE_FILES);

    protected SmbPath smbPath;
    protected final TreeConnect treeConnect;
    private AtomicBoolean disconnected = new AtomicBoolean(false);

    Share(SmbPath smbPath, TreeConnect treeConnect) {
        this.smbPath = smbPath;
        this.treeConnect = treeConnect;
    }

    @Override
    public void close() throws IOException {
        if (!disconnected.getAndSet(true)) {
            treeConnect.close();
        }
    }

    public boolean isConnected() {
        return !disconnected.get();
    }

    public TreeConnect getTreeConnect() {
        return treeConnect;
    }

    SMB2FileId openFileId(String path, long accessMask, Set<FileAttributes> fileAttributes, Set<SMB2ShareAccess> shareAccess, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        return createFile(path, accessMask, fileAttributes, shareAccess, createDisposition, createOptions).getFileId();
    }

    SMB2CreateResponse createFile(String path, long accessMask, Set<FileAttributes> fileAttributes, Set<SMB2ShareAccess> shareAccess, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        logger.info("open {},{}", path, fileAttributes);

        Session session = treeConnect.getSession();

        SMB2CreateRequest cr = new SMB2CreateRequest(
            session.getConnection().getNegotiatedProtocol().getDialect(),
            session.getSessionId(), treeConnect.getTreeId(),
            accessMask,
            fileAttributes,
            shareAccess,
            createDisposition,
            createOptions,
            path
        );

        return sendReceive(session, cr, "Create", path, SUCCESS);
    }

    void flush(SMB2FileId fileId) throws SMBApiException {
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();
        SMB2Flush flushReq = new SMB2Flush(
            connection.getNegotiatedProtocol().getDialect(),
            fileId
        );
        sendReceive(session, flushReq, "Flush", fileId, SUCCESS);
    }

    void closeFileId(SMB2FileId fileId) throws SMBApiException {
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();
        SMB2Close closeReq = new SMB2Close(
            connection.getNegotiatedProtocol().getDialect(),
            treeConnect.getSession().getSessionId(), treeConnect.getTreeId(), fileId);
        sendReceive(session, closeReq, "Close", fileId, SUCCESS);
    }

    SMB2QueryInfoResponse queryInfo(SMB2FileId fileId, SMB2QueryInfoRequest.SMB2QueryInfoType infoType, Set<SecurityInformation> securityInfo, FileInformationClass fileInformationClass, FileSystemInformationClass fileSystemInformationClass) {
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        SMB2QueryInfoRequest qreq = new SMB2QueryInfoRequest(
            connection.getNegotiatedProtocol().getDialect(),
            session.getSessionId(), treeConnect.getTreeId(),
            fileId, infoType,
            fileInformationClass, fileSystemInformationClass, null, securityInfo
        );
        return sendReceive(session, qreq, "QueryInfo", fileId, SUCCESS);
    }

    SMB2SetInfoResponse setInfo(SMB2FileId fileId, SMB2SetInfoRequest.SMB2InfoType infoType, Set<SecurityInformation> securityInfo, FileInformationClass fileInformationClass, byte[] buffer) {
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        SMB2SetInfoRequest qreq = new SMB2SetInfoRequest(
            connection.getNegotiatedProtocol().getDialect(),
            session.getSessionId(), treeConnect.getTreeId(),
            infoType, fileId,
            fileInformationClass, securityInfo, buffer
        );
        return sendReceive(session, qreq, "SetInfo", fileId, SUCCESS);
    }

    SMB2QueryDirectoryResponse queryDirectory(SMB2FileId fileId, Set<SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags> flags, FileInformationClass informationClass) {
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        SMB2QueryDirectoryRequest qdr = new SMB2QueryDirectoryRequest(
            connection.getNegotiatedProtocol().getDialect(),
            session.getSessionId(), treeConnect.getTreeId(),
            fileId, informationClass,
            flags,
            0, null);

        return sendReceive(session, qdr, "Query directory", fileId, SUCCESS_OR_NO_MORE_FILES);
    }

    private <T extends SMB2Packet> T sendReceive(Session session, SMB2Packet request, String name, Object target, Set<NtStatus> successResponses) {
        try {
            Future<T> fut = session.send(request);
            T resp = Futures.get(fut, TransportException.Wrapper);

            NtStatus status = resp.getHeader().getStatus();
            if (!successResponses.contains(status)) {
                throw new SMBApiException(resp.getHeader(), name + " failed for " + target);
            }
            return resp;
        } catch (TransportException e) {
            throw new SMBRuntimeException(e);
        }
    }
}
