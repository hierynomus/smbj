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

import com.hierynomus.msdtyp.SecurityInformation;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.FileInformationClass;
import com.hierynomus.msfscc.fileinformation.FileInformation;
import com.hierynomus.msfscc.fileinformation.FileInformationFactory;
import com.hierynomus.msfscc.fileinformation.FileSettableInformation;
import com.hierynomus.mssmb2.messages.SMB2SetInfoRequest;
import com.hierynomus.mssmb2.messages.SMB2SetInfoResponse;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.transport.TransportException;

import java.util.EnumSet;
import java.util.concurrent.Future;

abstract class DiskEntry {
    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    protected TreeConnect treeConnect;
    protected SMB2FileId fileId;
    protected String fileName;

    public DiskEntry(TreeConnect treeConnect, SMB2FileId fileId, String fileName) {
        this.treeConnect = treeConnect;
        this.fileId = fileId;
        this.fileName = fileName;
    }

    public void close() throws TransportException, SMBApiException {
        treeConnect.getHandle().close(fileId);
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

    /**
     * Get information for a given fileId
     **/
    protected  <F extends FileSettableInformation> void setFileInformation(F information) throws SMBApiException, TransportException {
        FileInformation.Encoder<F> encoder = FileInformationFactory.getEncoder(information);

        Buffer.PlainBuffer buffer = new Buffer.PlainBuffer(Buffer.DEFAULT_SIZE, Endian.LE);
        encoder.write(information, buffer);
        byte[] info = buffer.getCompactData();

        setInfoCommon(
            this.fileId,
            SMB2SetInfoRequest.SMB2InfoType.SMB2_0_INFO_FILE,
            null,
            encoder.getInformationClass(),
            info
        );
    }

    protected void setInfoCommon(
        SMB2FileId fileId,
        SMB2SetInfoRequest.SMB2InfoType infoType,
        EnumSet<SecurityInformation> securityInfo,
        FileInformationClass fileInformationClass,
        byte[] buffer)
        throws SMBApiException {

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        SMB2SetInfoRequest qreq = new SMB2SetInfoRequest(
            connection.getNegotiatedProtocol().getDialect(), session.getSessionId(), treeConnect.getTreeId(),
            infoType, fileId,
            fileInformationClass, securityInfo, buffer);
        try {
            Future<SMB2SetInfoResponse> qiResponseFuture = session.send(qreq);
            SMB2SetInfoResponse qresp = Futures.get(qiResponseFuture, SMBRuntimeException.Wrapper);

            if (qresp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                throw new SMBApiException(qresp.getHeader(), "SET_INFO failed for " + fileId);
            }
        } catch (TransportException e) {
            throw SMBRuntimeException.Wrapper.wrap(e);
        }
    }
}
