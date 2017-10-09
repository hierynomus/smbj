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
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.mssmb2.messages.SMB2CreateResponse;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.EnumSet;
import java.util.Set;

public class DFSDiskShare extends DiskShare {
    private static final Logger logger = LoggerFactory.getLogger(DFSDiskShare.class);
    private final DFSPathResolver dfsPathResolver;

    public DFSDiskShare(SmbPath smbPath, TreeConnect treeConnect) {
        super(smbPath, treeConnect);
        dfsPathResolver = new DFSPathResolver();
    }

    @Override
    public DiskEntry open(String path, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        SMB2CreateResponse response = createFile(path, null, accessMask, attributes, shareAccesses, createDisposition, createOptions);
        if (response.getHeader().getStatus() == NtStatus.STATUS_PATH_NOT_COVERED) {
            logger.info("DFS Share {} does not cover {}, resolve through DFS", this, path);
            try {
                SmbPath smbPath = new SmbPath(getSmbPath(), path);
                SmbPath resolved = SmbPath.parse(dfsPathResolver.resolve(getTreeConnect().getSession(), smbPath.toUncPath()));
                logger.info("DFS resolved {} -> {}", smbPath, resolved);
                if (!resolved.getHostname().equals(smbPath.getHostname())) {
                    // Ugly anti-Demeter... but first make it work
                    SMBClient client = getTreeConnect().getConnection().getClient();
                    try {
                        Connection connect = client.connect(resolved.getHostname());
                        Session session = connect.authenticate(getTreeConnect().getSession().getAuthenticationContext());
                        DiskShare share = (DiskShare) session.connectShare(resolved.getShareName());
                        return share.open(resolved.getPath(), accessMask, attributes, shareAccesses, createDisposition, createOptions);
                    } catch (IOException e) {
                        throw new SMBApiException(response.getHeader(), "Cannot connect to resolved path " + resolved, e);
                    }
                }
            } catch (PathResolveException e) {
                throw new SMBApiException(response.getHeader(), "Cannot resolve DFS path for " + path);
            }
        }
        return getDiskEntry(path, response);
    }

    @Override
    protected EnumSet<NtStatus> getCreateSuccessStatus() {
        EnumSet<NtStatus> status = EnumSet.copyOf(super.getCreateSuccessStatus());
        status.add(NtStatus.STATUS_PATH_NOT_COVERED);
        return status;
    }
}
