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
import com.hierynomus.mssmb2.messages.SMB2QueryDirectoryRequest;
import com.hierynomus.mssmb2.messages.SMB2QueryDirectoryResponse;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.Future;

public class Directory extends DiskEntry implements Iterable<FileInfo> {

    private static final Logger logger = LoggerFactory.getLogger(Directory.class);

    public Directory(SMB2FileId fileId, TreeConnect treeConnect, String fileName) {
        super(treeConnect, fileId, fileName);
    }

    public List<FileInfo> list() throws TransportException, SMBApiException {
        List<FileInfo> fileList = new ArrayList<>();
        for (FileInfo fileInfo : this) {
            fileList.add(fileInfo);
        }
        return fileList;
    }

    @Override
    public Iterator<FileInfo> iterator() {
        return new DirectoryIterator();
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

    private class DirectoryIterator implements Iterator<FileInfo> {
        private Iterator<FileInfo> currentIterator;
        private FileInfo next;

        DirectoryIterator() {
            currentIterator = queryDirectory(true);
            this.next = prepareNext();
        }

        @Override
        public boolean hasNext() {
            return next != null;
        }

        @Override
        public FileInfo next() {
            if (!hasNext()) {
                throw new NoSuchElementException();
            }

            FileInfo fileInfo = this.next;
            this.next = prepareNext();
            return fileInfo;
        }

        private FileInfo prepareNext() {
            while (currentIterator != null) {
                if (currentIterator.hasNext()) {
                    return currentIterator.next();
                } else {
                    currentIterator = queryDirectory(false);
                }
            }
            return null;
        }

        private Iterator<FileInfo> queryDirectory(boolean firstQuery) {
            Session session = treeConnect.getSession();
            Connection connection = session.getConnection();

            // Query Directory Request
            EnumSet<SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags> flags;
            if (firstQuery) {
                flags = EnumSet.of(SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags.SMB2_RESTART_SCANS);
            } else {
                flags = EnumSet.noneOf(SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags.class);
            }

            SMB2QueryDirectoryRequest qdr = new SMB2QueryDirectoryRequest(connection.getNegotiatedProtocol().getDialect(),
                session.getSessionId(), treeConnect.getTreeId(),
                getFileId(), FileInformationClass.FileIdBothDirectoryInformation,
                flags,
                0, null);

            SMB2QueryDirectoryResponse qdResp;
            try {
                Future<SMB2QueryDirectoryResponse> qdFuture = session.send(qdr);
                qdResp = Futures.get(qdFuture, TransportException.Wrapper);
            } catch (TransportException e) {
                throw new SMBRuntimeException(e);
            }

            NtStatus status = qdResp.getHeader().getStatus();

            if (status == NtStatus.STATUS_NO_MORE_FILES) {
                return null;
            } else {
                if (status != NtStatus.STATUS_SUCCESS) {
                    throw new SMBApiException(qdResp.getHeader(), String.format("Query directory failed for %s", this));
                }
                return FileInformationFactory.createFileInformationIterator(
                    qdResp.getOutputBuffer(),
                    FileInformationClass.FileIdBothDirectoryInformation
                );
            }
        }

        @Override
        public void remove() {
            throw new UnsupportedOperationException();
        }
    }
}
