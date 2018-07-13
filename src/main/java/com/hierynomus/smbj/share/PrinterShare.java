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
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.smbj.ProgressListener;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.io.ByteChunkProvider;
import com.hierynomus.smbj.io.InputStreamByteChunkProvider;

import java.io.InputStream;
import java.util.EnumSet;

public class PrinterShare extends Share {

    public PrinterShare(SmbPath smbPath, TreeConnect treeConnect) {
        super(smbPath, treeConnect);
    }

    public void print(InputStream inputStream) {
        print(inputStream, null);
    }

    public void print(InputStream inputStream, ProgressListener progressListener) {
        print(new InputStreamByteChunkProvider(inputStream), progressListener);
    }

    public void print(ByteChunkProvider provider) {
        print(provider, null);
    }

    public void print(ByteChunkProvider provider, ProgressListener progressListener) {
        SMB2FileId fileId = openFileId(null,
            null,
            null,
            EnumSet.of(AccessMask.FILE_WRITE_DATA),
            EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
            EnumSet.of(SMB2ShareAccess.FILE_SHARE_WRITE),
            SMB2CreateDisposition.FILE_CREATE,
            EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE, SMB2CreateOptions.FILE_WRITE_THROUGH));
        try {
            new SMB2Writer(this, fileId, getSmbPath().toString()).write(provider, progressListener);
        } finally {
            closeFileId(fileId);
        }
    }
}
