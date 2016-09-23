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
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.Future;

public class Directory extends DiskEntry {

    private static final Logger logger = LoggerFactory.getLogger(Directory.class);

    public Directory(SMB2FileId fileId, TreeConnect treeConnect, String fileName) {
        super(treeConnect, fileId, fileName);
    }

    public List<FileInfo> list() throws TransportException, SMBApiException {
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();
        int index = 0;
        int newDataLength = -1;
        List<FileInfo> fileList = new ArrayList<FileInfo>();

        // Keep querying until we don't get new data
        do {
            // Query Directory Request
            SMB2QueryDirectoryRequest qdr = new SMB2QueryDirectoryRequest(connection.getNegotiatedDialect(),
                    session.getSessionId(), treeConnect.getTreeId(),
                    getFileId(), FileInformationClass.FileIdBothDirectoryInformation, // FileInformationClass
                    // .FileDirectoryInformation,
                    EnumSet.of(SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags.SMB2_INDEX_SPECIFIED),
                    index, null);
            Future<SMB2QueryDirectoryResponse> qdFuture = connection.send(qdr);

            SMB2QueryDirectoryResponse qdResp = Futures.get(qdFuture, TransportException.Wrapper);

            if (qdResp.getHeader().getStatus() == NtStatus.STATUS_NO_MORE_FILES) {
                newDataLength = 0;
            } else {
                if (qdResp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                    throw new SMBApiException(qdResp.getHeader().getStatus(),
                            qdResp.getHeader().getStatusCode(),
                            "Query directory failed for " + fileName + "/" + fileId);
                }
                byte[] outputBuffer = qdResp.getOutputBuffer();
                newDataLength = outputBuffer.length;
                index += newDataLength;

                try {
                    fileList.addAll(FileInformationFactory.parseFileInformationList(outputBuffer, FileInformationClass.FileIdBothDirectoryInformation));
                } catch (Buffer.BufferException e) {
                    throw new TransportException(e);
                }
            }
        } while(newDataLength > 65000); // Optimization for not making the last call which returns NO_MORE_FILES.

        return fileList;
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

}
