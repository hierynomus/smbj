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

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.session.Session;

import java.util.EnumSet;
import java.util.Set;

public interface PathResolver {
    PathResolver LOCAL = new PathResolver() {
        @Override
        public SmbPath resolve(Session session, SMB2Packet responsePacket, SmbPath smbPath) {
            return smbPath;
        }

        @Override
        public Set<NtStatus> handledStates() {
            return EnumSet.of(NtStatus.STATUS_SUCCESS);
        }
    };

    SmbPath resolve(Session session, SMB2Packet responsePacket, SmbPath smbPath) throws PathResolveException;

    Set<NtStatus> handledStates();
}
