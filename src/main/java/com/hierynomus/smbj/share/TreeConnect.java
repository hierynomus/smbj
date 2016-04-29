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

import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.smb2.SMB2ShareCapabilities;

import java.util.EnumSet;

/**
 *
 */
public class TreeConnect {

    private long treeId;
    private Session session;
    private final boolean isDfsShare;
    private final boolean isCAShare;
    private final boolean isScaleoutShare;

    public TreeConnect(long treeId, Session session, EnumSet<SMB2ShareCapabilities> capabilities) {
        this.treeId = treeId;
        this.session = session;
        this.isDfsShare = capabilities.contains(SMB2ShareCapabilities.SMB2_SHARE_CAP_DFS);
        this.isCAShare = capabilities.contains(SMB2ShareCapabilities.SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY);
        this.isScaleoutShare = capabilities.contains(SMB2ShareCapabilities.SMB2_SHARE_CAP_SCALEOUT);
    }
}
