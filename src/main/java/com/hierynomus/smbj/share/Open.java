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

import java.io.Closeable;

import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.smbj.common.SmbPath;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Open<S extends Share> implements Closeable {
    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    protected S share;
    protected SMB2FileId fileId;
    protected SmbPath name;

    Open(SMB2FileId fileId, SmbPath name, S share) {
        this.fileId = fileId;
        this.name = name;
        this.share = share;
    }


    public SMB2FileId getFileId() {
        return fileId;
    }

    public void close() {
        share.closeFileId(fileId);
    }

    public void closeSilently() {
        try {
            close();
        } catch (Exception e) {
            logger.warn("{} close failed for {},{},{}", this.getClass().getSimpleName(), name, share, fileId, e);
        }
    }
}
