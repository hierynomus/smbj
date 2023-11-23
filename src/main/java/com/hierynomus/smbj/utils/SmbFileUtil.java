/*
 * Copyright (C)2023 - SMBJ Contributors
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

import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.share.DiskShare;

/**
 * Utility class for working with files and paths
 */
public class SmbFileUtil {

    private static final SmbFiles SMB_FILES = new SmbFiles();

    private SmbFileUtil() {
        // private as this utility class should not be instantiated
    }

    /**
     * Creates a set of nested subdirectories in the given path, for example, 2345\3456\4453\123123.txt
     *
     * @param diskShare the share
     * @param path      the path to create
     * @throws SMBApiException when an SMB error occurs
     */
    public void mkdirs(DiskShare diskShare, String path) throws SMBApiException {
        SMB_FILES.mkdirs(diskShare, path);
    }

    /**
     * Creates a set of nested subdirectories in the given path, for example, 2345\3456\4453\123123.txt
     *
     * @param diskShare the share
     * @param path      the path to create
     * @throws SMBApiException when an SMB error occurs
     */
    public void mkdirs(DiskShare diskShare, SmbPath path) throws SMBApiException {
        SMB_FILES.mkdirs(diskShare, path);
    }

}
