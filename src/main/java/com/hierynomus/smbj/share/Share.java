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
import com.hierynomus.msdtyp.SecurityInformation;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.FileInformationClass;
import com.hierynomus.msfscc.FileSystemInformationClass;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.*;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.Config;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.connection.NegotiatedProtocol;
import com.hierynomus.smbj.io.ByteChunkProvider;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.TransportException;

import java.io.IOException;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

public class Share implements AutoCloseable {
    private static final EnumSet<NtStatus> SUCCESS = EnumSet.of(NtStatus.STATUS_SUCCESS);
    private static final EnumSet<NtStatus> SUCCESS_OR_NO_MORE_FILES = EnumSet.of(NtStatus.STATUS_SUCCESS, NtStatus.STATUS_NO_MORE_FILES);

    private final SmbPath smbPath;
    private final TreeConnect treeConnect;
    private final long treeId;
    private final Session session;
    private final SMB2Dialect dialect;
    private final int readBufferSize;
    private final int writeBufferSize;
    private final int transactBufferSize;
    private final long sessionId;
    private final AtomicBoolean disconnected = new AtomicBoolean(false);

    Share(SmbPath smbPath, TreeConnect treeConnect) {
        this.smbPath = smbPath;
        this.treeConnect = treeConnect;
        session = treeConnect.getSession();
        Connection connection = treeConnect.getConnection();
        NegotiatedProtocol negotiatedProtocol = connection.getNegotiatedProtocol();
        dialect = negotiatedProtocol.getDialect();
        Config config = connection.getConfig();
        readBufferSize = Math.min(config.getReadBufferSize(), negotiatedProtocol.getMaxReadSize());
        writeBufferSize = Math.min(config.getWriteBufferSize(), negotiatedProtocol.getMaxWriteSize());
        transactBufferSize = Math.min(config.getTransactBufferSize(), negotiatedProtocol.getMaxTransactSize());
        sessionId = session.getSessionId();
        treeId = treeConnect.getTreeId();
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

    public SmbPath getSmbPath() {
        return smbPath;
    }

    public TreeConnect getTreeConnect() {
        return treeConnect;
    }

    int getReadBufferSize() {
        return readBufferSize;
    }

    int getWriteBufferSize() {
        return writeBufferSize;
    }

    SMB2FileId openFileId(String path, Set<AccessMask> accessMask, Set<FileAttributes> fileAttributes, Set<SMB2ShareAccess> shareAccess, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        return createFile(path, accessMask, fileAttributes, shareAccess, createDisposition, createOptions).getFileId();
    }

    SMB2CreateResponse createFile(String path, Set<AccessMask> accessMask, Set<FileAttributes> fileAttributes, Set<SMB2ShareAccess> shareAccess, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        SMB2CreateRequest cr = new SMB2CreateRequest(
            dialect,
            sessionId, treeId,
            accessMask,
            fileAttributes,
            shareAccess,
            createDisposition,
            createOptions,
            path
        );

        return sendReceive(cr, "Create", path, SUCCESS);
    }

    void flush(SMB2FileId fileId) throws SMBApiException {
        SMB2Flush flushReq = new SMB2Flush(
            dialect,
            fileId
        );
        sendReceive(flushReq, "Flush", fileId, SUCCESS);
    }

    void closeFileId(SMB2FileId fileId) throws SMBApiException {
        SMB2Close closeReq = new SMB2Close(dialect, sessionId, treeId, fileId);
        sendReceive(closeReq, "Close", fileId, SUCCESS);
    }

    SMB2QueryInfoResponse queryInfo(SMB2FileId fileId, SMB2QueryInfoRequest.SMB2QueryInfoType infoType, Set<SecurityInformation> securityInfo, FileInformationClass fileInformationClass, FileSystemInformationClass fileSystemInformationClass) {
        SMB2QueryInfoRequest qreq = new SMB2QueryInfoRequest(
            dialect,
            sessionId, treeId,
            fileId, infoType,
            fileInformationClass, fileSystemInformationClass, null, securityInfo
        );
        return sendReceive(qreq, "QueryInfo", fileId, SUCCESS);
    }

    SMB2SetInfoResponse setInfo(SMB2FileId fileId, SMB2SetInfoRequest.SMB2InfoType infoType, Set<SecurityInformation> securityInfo, FileInformationClass fileInformationClass, byte[] buffer) {
        SMB2SetInfoRequest qreq = new SMB2SetInfoRequest(
            dialect,
            sessionId, treeId,
            infoType, fileId,
            fileInformationClass, securityInfo, buffer
        );
        return sendReceive(qreq, "SetInfo", fileId, SUCCESS);
    }

    SMB2QueryDirectoryResponse queryDirectory(SMB2FileId fileId, Set<SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags> flags, FileInformationClass informationClass) {
        SMB2QueryDirectoryRequest qdr = new SMB2QueryDirectoryRequest(
            dialect,
            sessionId, treeId,
            fileId, informationClass,
            flags,
            0,
            null,
            transactBufferSize
        );

        return sendReceive(qdr, "Query directory", fileId, SUCCESS_OR_NO_MORE_FILES);
    }

    SMB2WriteResponse write(SMB2FileId fileId, ByteChunkProvider provider) {
        SMB2WriteRequest wreq = new SMB2WriteRequest(
            dialect,
            fileId,
            sessionId, treeId,
            provider,
            writeBufferSize
        );
        return sendReceive(wreq, "Write", fileId, SUCCESS);
    }

    SMB2ReadResponse read(SMB2FileId fileId, long offset, int length) {
        return receive(
            readAsync(fileId, offset, length),
            "Read",
            fileId,
            SUCCESS
        );
    }

    Future<SMB2ReadResponse> readAsync(SMB2FileId fileId, long offset, int length) {
        SMB2ReadRequest rreq = new SMB2ReadRequest(
            dialect,
            fileId,
            sessionId, treeId,
            offset,
            Math.min(length, readBufferSize)
        );
        return send(rreq);
    }

    private <T extends SMB2Packet> T sendReceive(SMB2Packet request, String name, Object target, Set<NtStatus> successResponses) {
        Future<T> fut = send(request);
        return receive(fut, name, target, successResponses);
    }

    private <T extends SMB2Packet> Future<T> send(SMB2Packet request) {
        try {
            return session.send(request);
        } catch (TransportException e) {
            throw new SMBRuntimeException(e);
        }
    }

    private <T extends SMB2Packet> T receive(Future<T> fut, String name, Object target, Set<NtStatus> successResponses) {
        T resp;
        try {
            resp = Futures.get(fut, TransportException.Wrapper);
        } catch (TransportException e) {
            throw new SMBRuntimeException(e);
        }

        NtStatus status = resp.getHeader().getStatus();
        if (!successResponses.contains(status)) {
            throw new SMBApiException(resp.getHeader(), name + " failed for " + target);
        }
        return resp;
    }
}
