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
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.FileInformationClass;
import com.hierynomus.msfscc.fileinformation.FileInfo;
import com.hierynomus.msfscc.fileinformation.FileInformationFactory;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.smb2.SMB2CreateDisposition;
import com.hierynomus.smbj.smb2.SMB2CreateOptions;
import com.hierynomus.smbj.smb2.SMB2FileId;
import com.hierynomus.smbj.smb2.SMB2ShareAccess;
import com.hierynomus.smbj.smb2.messages.SMB2Close;
import com.hierynomus.smbj.smb2.messages.SMB2QueryDirectoryRequest;
import com.hierynomus.smbj.smb2.messages.SMB2QueryDirectoryResponse;
import com.hierynomus.smbj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.Future;

public class Directory {

    private static final Logger logger = LoggerFactory.getLogger(Directory.class);

    SMB2FileId fileId;
    TreeConnect treeConnect;
    String fileName;

    EnumSet<AccessMask> accessMask; // The Access the current user has on the file.
    EnumSet<SMB2ShareAccess> shareAccess;
    SMB2CreateDisposition createDisposition;

    public Directory(
            SMB2FileId fileId, TreeConnect treeConnect, String fileName, EnumSet<AccessMask> accessMask,
            EnumSet<SMB2ShareAccess> shareAccess, SMB2CreateDisposition createDisposition) {
        this.fileId = fileId;
        this.treeConnect = treeConnect;
        this.fileName = fileName;
        this.accessMask = accessMask;
        this.shareAccess = shareAccess;
        this.createDisposition = createDisposition;
    }

    public List<FileInfo> list() throws TransportException, SMBApiException {
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        // Query Directory Request
        SMB2QueryDirectoryRequest qdr = new SMB2QueryDirectoryRequest(connection.getNegotiatedDialect(),
                session.getSessionId(), treeConnect.getTreeId(),
                getFileId(), FileInformationClass.FileIdBothDirectoryInformation, // FileInformationClass
                // .FileDirectoryInformation,
                EnumSet.of(SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags.SMB2_REOPEN),
                0, null);
        Future<SMB2QueryDirectoryResponse> qdFuture = connection.send(qdr);

        SMB2QueryDirectoryResponse qdResp = Futures.get(qdFuture, TransportException.Wrapper);

        if (qdResp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(qdResp.getHeader().getStatus(),
                    "Query directory failed for " + fileName + "/" + fileId);
        }
        byte[] outputBuffer = qdResp.getOutputBuffer();

        try {
            return FileInformationFactory.parseFileInformationList(
                    outputBuffer, FileInformationClass.FileIdBothDirectoryInformation);
        } catch (Buffer.BufferException e) {
            throw new TransportException(e);
        }
    }

    public SMB2FileId getFileId() {
        return fileId;
    }

    public void close() throws TransportException, SMBApiException {
        Connection connection = treeConnect.getSession().getConnection();
        SMB2Close closeReq = new SMB2Close(
                connection.getNegotiatedDialect(),
                treeConnect.getSession().getSessionId(), treeConnect.getTreeId(), fileId);
        Future<SMB2Close> closeFuture = connection.send(closeReq);
        SMB2Close closeResp = Futures.get(closeFuture, TransportException.Wrapper);

        if (closeResp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(closeResp.getHeader().getStatus(), "Close failed for " + fileId);
        }
    }

    public void closeSilently() {
        try {
            close();
        } catch (Exception e) {
            logger.warn("File close failed for {},{},{}", fileName, treeConnect, fileId, e);
        }
    }

    @Override
    public String toString() {
        return "File{" +
                "fileId=" + fileId +
                ", fileName='" + fileName + '\'' +
                '}';
    }

}
