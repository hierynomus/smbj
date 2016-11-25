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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.transport.TransportException;

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

}
