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

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.FileInformationClass;
import com.hierynomus.msfscc.fileinformation.FileInfo;
import com.hierynomus.msfscc.fileinformation.FileInformationFactory;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.mssmb2.messages.SMB2QueryDirectoryRequest;
import com.hierynomus.mssmb2.messages.SMB2QueryDirectoryResponse;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Future;

public class Directory extends DiskEntry implements Iterable<FileInfo> {

    private static final Logger logger = LoggerFactory.getLogger(Directory.class);

    public Directory(SMB2FileId fileId, TreeConnect treeConnect, String fileName) {
        super(treeConnect, fileId, fileName);
    }

    private class IterableContextData {
        int newDataLength = -1;
        int iteratorIndex = 0;
        FileInfo next = null;
        List<FileInfo> entries = null;
        NtStatus lastStatus = NtStatus.UNKNOWN;
    }

    public List<FileInfo> list() throws TransportException, SMBApiException {
        List<FileInfo> fileList = new ArrayList<>();
        IterableContextData ctx = new IterableContextData();
        // Keep querying until we don't get new data
        do {
            query(ctx);

            if (ctx.entries != null) {
                fileList.addAll(ctx.entries);
            }
        } while (ctx.newDataLength > 65000); // Optimization for not making the last call which returns NO_MORE_FILES.

        return fileList;
    }

    private void query(IterableContextData ctx) throws TransportException {
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();
        // Query Directory Request
        EnumSet<SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags> smb2Reopen = EnumSet.noneOf(SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags.class);
        if (ctx.newDataLength < 0) {
            smb2Reopen = EnumSet.of(SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags.SMB2_RESTART_SCANS);
        }
        SMB2QueryDirectoryRequest qdr = new SMB2QueryDirectoryRequest(connection.getNegotiatedProtocol().getDialect(),
            session.getSessionId(), treeConnect.getTreeId(),
            getFileId(), FileInformationClass.FileIdBothDirectoryInformation,
            smb2Reopen,
            0, null);
        Future<SMB2QueryDirectoryResponse> qdFuture = session.send(qdr);

        SMB2QueryDirectoryResponse qdResp = Futures.get(qdFuture, TransportException.Wrapper);

        ctx.lastStatus = qdResp.getHeader().getStatus();
        if (qdResp.getHeader().getStatus() == NtStatus.STATUS_NO_MORE_FILES) {
            ctx.newDataLength = 0;
            ctx.entries = null;
        } else {
            if (qdResp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                throw new SMBApiException(qdResp.getHeader().getStatus(),
                    qdResp.getHeader().getStatusCode(), SMB2MessageCommandCode.SMB2_QUERY_DIRECTORY,
                    "Query directory failed for " + fileName + "/" + fileId);
            }
            byte[] outputBuffer = qdResp.getOutputBuffer();
            ctx.newDataLength = outputBuffer.length;

            try {
                ctx.entries = FileInformationFactory.parseFileInformationList(outputBuffer, FileInformationClass.FileIdBothDirectoryInformation);
            } catch (Buffer.BufferException e) {
                throw new TransportException(e);
            }

        }
    }

    public SMB2FileId getFileId() {
        return fileId;
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
        return String.format("File{fileId=%s, fileName='%s'}", fileId, fileName);
    }

    @Override
    public Iterator<FileInfo> iterator() {
        return new Iterator<FileInfo>() {

            IterableContextData ctx = new IterableContextData();

            @Override
            public boolean hasNext() {
                try {
                    queryIfNeeded();
                } catch (TransportException e) {
                    throw new SMBRuntimeException(e);
                }
                return ctx.next != null;
            }

            void queryIfNeeded() throws TransportException {

                if (ctx.newDataLength < 0) {
                    query(ctx);
                }
                if (ctx.entries == null || ctx.entries.size() == 0 || ctx.lastStatus == NtStatus.STATUS_NO_MORE_FILES) {
                    if (ctx.iteratorIndex > 0) {
                        ctx.next = null;
                    }
                } else if (ctx.iteratorIndex == ctx.entries.size() - 1) {
                    ctx.next = ctx.entries.get(ctx.entries.size() - 1);
                    ctx.iteratorIndex = 0;
                    query(ctx);
                } else {
                    ctx.next = ctx.entries.get(ctx.iteratorIndex);
                }
            }

            @Override
            public void remove() {
                throw new UnsupportedOperationException("remove");
            }

            @Override
            public FileInfo next() {
                try {
                    queryIfNeeded();
                    FileInfo next = ctx.next;
                    ctx.iteratorIndex++;
                    return next;
                } catch (TransportException e) {
                    throw new SMBRuntimeException(e);
                }
            }
        };
    }
}
