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
package com.hierynomus.smbj.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.EnumSet;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.io.InputStreamByteChunkProvider;
import com.hierynomus.smbj.share.DiskShare;

public class SmbFiles {

    /**
     * Copies a local file to a destination path on the share
     *
     * @param share     the share
     * @param destPath  the path to write to
     * @param source    the local File
     * @param overwrite true/false to overwrite existing file
     * @return the actual number of bytes that was written to the file
     * @throws FileNotFoundException file with the specified pathname does not exist
     * @throws IOException file could not be read
     */
    public static long copy(File source, DiskShare share, String destPath, boolean overwrite) throws IOException {
        long bytesWritten = 0L;
        if (source != null && source.exists() && source.canRead() && source.isFile()) {
            try (InputStream is = new FileInputStream(source)) {
                bytesWritten = write(is, share, destPath, overwrite);
            }
        }
        return bytesWritten;
    }

    /**
     * Writes an input stream to a destination path on the share
     *
     * @param source    the local File
     * @param share     the share
     * @param destPath  the path to write to
     * @param overwrite true/false to overwrite existing file
     * @return the actual number of bytes that was written to the file
     */
    public static long write(InputStream source, DiskShare share, String destPath, boolean overwrite) {
        long bytesWritten = 0L;
        if (destPath != null && source != null) {
            try (com.hierynomus.smbj.share.File file = share.openFile(
                destPath,
                EnumSet.of(AccessMask.GENERIC_WRITE),
                EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                EnumSet.of(SMB2ShareAccess.FILE_SHARE_WRITE),
                overwrite ? SMB2CreateDisposition.FILE_OVERWRITE_IF : SMB2CreateDisposition.FILE_CREATE,
                EnumSet.noneOf(SMB2CreateOptions.class)
            )) {
                bytesWritten = file.write(new InputStreamByteChunkProvider(source));
            }
        }
        return bytesWritten;
    }

    /**
     * Create a set of nested sub-directories in the given path, for example, 2345 \ 3456 \ 4453 \ 123123.txt
     */
    public void mkdirs(DiskShare diskShare, String path) throws SMBApiException {
        SmbPath smbPath = new SmbPath(diskShare.getSmbPath(), path);
        mkdirs(diskShare, smbPath);
    }

    /**
     * Create a set of nested sub-directories in the given path, for example, 2345 \ 3456 \ 4453 \ 123123.txt
     */
    public void mkdirs(DiskShare diskShare, SmbPath path) throws SMBApiException {
        if (!diskShare.folderExists(path.getPath())) {
            // Ensure the parent path exists
            mkdirs(diskShare, path.getParent());
            diskShare.mkdir(path.getPath());
        }
    }
}
