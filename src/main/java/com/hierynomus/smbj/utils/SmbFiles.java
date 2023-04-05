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
     * Copies local file to a destination path on the share
     *
     * @param share     the share
     * @param destPath  the path to write to
     * @param source    the local File
     * @param overwrite true/false to overwrite existing file
     * @return the actual number of bytes that was written to the file
     * @throws java.io.FileNotFoundException
     * @throws java.io.IOException
     */
    public static long copy(File source, DiskShare share, String destPath, boolean overwrite) throws IOException {
        long r = 0;
        if (source != null && source.exists() && source.canRead() && source.isFile()) {

            try (InputStream is = new java.io.FileInputStream(source)) {
                if (destPath != null && is != null) {
                    try (com.hierynomus.smbj.share.File f = share.openFile(
                        destPath,
                        EnumSet.of(AccessMask.GENERIC_WRITE),
                        EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                        EnumSet.of(SMB2ShareAccess.FILE_SHARE_WRITE),
                        (overwrite ? SMB2CreateDisposition.FILE_OVERWRITE_IF : SMB2CreateDisposition.FILE_CREATE),
                        EnumSet.noneOf(SMB2CreateOptions.class)
                    )) {
                        r = f.write(new InputStreamByteChunkProvider(is));
                    }
                }
            }
        }
        return r;
    }

    /**
     * Create a set of nested sub-directories in the given path, for example, 2345 \ 3456 \ 4453 \ 123123.txt
     */
    public static void mkdirs(DiskShare diskShare, String path, boolean pathIsFile) throws SMBApiException {
        SmbPath smbPath = new SmbPath(diskShare.getSmbPath(), path);
        mkdirs(diskShare, smbPath, pathIsFile);
    }

    /**
     * Create a set of nested sub-directories in the given path, for example, 2345 \ 3456 \ 4453 \ 123123.txt
     */
    public static void mkdirs(DiskShare diskShare, SmbPath path, boolean pathIsFile) throws SMBApiException {
        if (pathIsFile) {
            path = path.getParent();
        }
        if (!diskShare.folderExists(path.getPath())) {
            // Ensure the parent path exists
            mkdirs(diskShare, path.getParent(), false);
            diskShare.mkdir(path.getPath());
        }
    }
}
