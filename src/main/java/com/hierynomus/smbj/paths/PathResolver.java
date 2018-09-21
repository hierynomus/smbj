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
package com.hierynomus.smbj.paths;

import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.StatusHandler;

public interface PathResolver {
    PathResolver LOCAL = new PathResolver() {
        @Override
        public SmbPath resolve(Session session, SMB2Packet responsePacket, SmbPath smbPath) {
            return smbPath;
        }

        @Override
        public SmbPath resolve(Session session, SmbPath smbPath) {
            return smbPath;
        }

        public StatusHandler statusHandler() {
            return StatusHandler.SUCCESS;
        }
    };

    /**
     * Reactive path resolution based on response packet
     * @param session
     * @param responsePacket
     * @param smbPath
     * @return
     * @throws PathResolveException
     */
    SmbPath resolve(Session session, SMB2Packet responsePacket, SmbPath smbPath) throws PathResolveException;

    /**
     * Proactive path resolution based on response packet
     * @param session
     * @param smbPath
     * @return
     * @throws PathResolveException
     */
    SmbPath resolve(Session session, SmbPath smbPath) throws PathResolveException;

    StatusHandler statusHandler();
}
