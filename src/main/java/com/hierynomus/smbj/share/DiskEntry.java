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

import com.hierynomus.msdtyp.SecurityDescriptor;
import com.hierynomus.msdtyp.SecurityInformation;
import com.hierynomus.msfscc.fileinformation.FileAllInformation;
import com.hierynomus.msfscc.fileinformation.FileQueryableInformation;
import com.hierynomus.msfscc.fileinformation.FileRenameInformation;
import com.hierynomus.msfscc.fileinformation.FileSettableInformation;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.util.Set;

public abstract class DiskEntry implements Closeable {
    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    protected DiskShare share;
    protected SMB2FileId fileId;
    protected String fileName;

    DiskEntry(DiskShare share, SMB2FileId fileId, String fileName) {
        this.share = share;
        this.fileId = fileId;
        this.fileName = fileName;
    }

    public void close() {
        share.closeFileId(fileId);
    }

    public SMB2FileId getFileId() {
        return fileId;
    }

    public FileAllInformation getFileInformation() throws SMBApiException, TransportException {
        return getFileInformation(FileAllInformation.class);
    }

    public <F extends FileQueryableInformation> F getFileInformation(Class<F> informationClass) throws SMBApiException {
        return share.getFileInformation(fileId, informationClass);
    }

    public <F extends FileSettableInformation> void setFileInformation(F information) {
        share.setFileInformation(fileId, information);
    }

    public SecurityDescriptor getSecurityInformation(Set<SecurityInformation> securityInfo) throws SMBApiException {
        return share.getSecurityInfo(fileId, securityInfo);
    }

    public void rename(String newName) throws SMBApiException {
        this.rename(newName, false);
    }

    public void rename(String newName, boolean replaceIfExist) throws SMBApiException {
        this.rename(newName, replaceIfExist, 0);
    }

    public void rename(String newName, boolean replaceIfExist, long rootDirectory) throws SMBApiException {
        FileRenameInformation renameInfo = new FileRenameInformation(replaceIfExist, rootDirectory, newName);
        this.setFileInformation(renameInfo);
    }

    public void flush() {
        share.flush(fileId);
    }

    public void deleteOnClose() {
        share.deleteOnClose(fileId);
    }

    public void closeSilently() {
        try {
            close();
        } catch (Exception e) {
            logger.warn("File close failed for {},{},{}", fileName, share, fileId, e);
        }
    }
}
