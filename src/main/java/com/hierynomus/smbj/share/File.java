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
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.ProgressListener;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.smb2.SMB2FileId;
import com.hierynomus.smbj.smb2.messages.SMB2ReadRequest;
import com.hierynomus.smbj.smb2.messages.SMB2ReadResponse;
import com.hierynomus.smbj.smb2.messages.SMB2WriteRequest;
import com.hierynomus.smbj.smb2.messages.SMB2WriteResponse;
import com.hierynomus.smbj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.Future;

public class File extends DiskEntry {

    private static final Logger logger = LoggerFactory.getLogger(File.class);

    public File(SMB2FileId fileId, TreeConnect treeConnect, String fileName) {
        super(treeConnect, fileId, fileName);
    }

    public void write(InputStream srcStream, ProgressListener progressListener) throws IOException, SMBApiException {

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        byte[] buf = new byte[connection.getNegotiatedProtocol().getMaxWriteSize()];
        int numRead = -1;
        int offset = 0;

        while ((numRead = srcStream.read(buf)) != -1) {
            //logger.debug("Writing {} bytes", numRead);
            SMB2WriteRequest wreq = new SMB2WriteRequest(connection.getNegotiatedProtocol().getDialect(), getFileId(),
                    session.getSessionId(), treeConnect.getTreeId(),
                    buf, numRead, offset, 0);
            Future<SMB2WriteResponse> writeFuture = connection.send(wreq);
            SMB2WriteResponse wresp = Futures.get(writeFuture, TransportException.Wrapper);

            if (wresp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                throw new SMBApiException(wresp.getHeader().getStatus(), "Write failed for " + this);
            }
            offset += numRead;
            if (progressListener != null) progressListener.onProgressChanged(offset, -1);
        }
    }

    public void read(OutputStream destStream, ProgressListener progressListener) throws IOException,
            SMBApiException {
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        long offset = 0;
        SMB2ReadRequest rreq = new SMB2ReadRequest(connection.getNegotiatedProtocol(), getFileId(),
                session.getSessionId(), treeConnect.getTreeId(), offset);

        Future<SMB2ReadResponse> readResponseFuture = connection.send(rreq);
        SMB2ReadResponse rresp = Futures.get(readResponseFuture, TransportException.Wrapper);

        while (rresp.getHeader().getStatus() == NtStatus.STATUS_SUCCESS &&
                rresp.getHeader().getStatus() != NtStatus.STATUS_END_OF_FILE) {
            destStream.write(rresp.getData());
            offset += rresp.getDataLength();
            rreq = new SMB2ReadRequest(connection.getNegotiatedProtocol(), getFileId(),
                    session.getSessionId(), treeConnect.getTreeId(), offset);
            readResponseFuture = connection.send(rreq);
            rresp = Futures.get(readResponseFuture, TransportException.Wrapper);
            if (progressListener != null) progressListener.onProgressChanged(offset, -1);
        }

        if (rresp.getHeader().getStatus() != NtStatus.STATUS_END_OF_FILE) {
            throw new SMBApiException(rresp.getHeader().getStatus(), "Read failed for " + this);
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
