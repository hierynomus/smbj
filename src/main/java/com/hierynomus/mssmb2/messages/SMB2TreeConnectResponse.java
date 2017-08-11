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
package com.hierynomus.mssmb2.messages;

import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2ShareCapabilities;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

import java.util.Set;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toEnumSet;

/**
 * [MS-SMB2].pdf 2.2.10 SMB2 TREE_CONNECT Response
 * <p>
 * TODO
 */
public class SMB2TreeConnectResponse extends SMB2Packet {

    private byte shareType;
    private long shareFlags;
    private Set<SMB2ShareCapabilities> capabilities;
    private long maximalAccess;

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        buffer.skip(2); // StructureSize (2 bytes)
        shareType = buffer.readByte(); // ShareType (1 byte)
        buffer.readByte(); // Reserved (1 byte)
        shareFlags = buffer.readUInt32(); // ShareFlags (4 bytes)
        capabilities = toEnumSet(buffer.readUInt32(), SMB2ShareCapabilities.class); // Capabilities (4 bytes)
        maximalAccess = buffer.readUInt32(); // MaximalAccess (4 bytes)
    }

    /**
     * Whether the ShareType returned is SMB2_SHARE_TYPE_DISK (0x01)
     *
     * @return true if the ShareType returned is SMB2_SHARE_TYPE_DISK (0x01)
     */
    public boolean isDiskShare() {
        return shareType == 0x01;
    }

    /**
     * Whether the ShareType returned is SMB2_SHARE_TYPE_PIPE (0x02)
     *
     * @return true if the ShareType returned is SMB2_SHARE_TYPE_PIPE (0x02)
     */
    public boolean isNamedPipe() {
        return shareType == 0x02;
    }

    /**
     * Whether the ShareType returned is SMB2_SHARE_TYPE_PRINT (0x03)
     *
     * @return true if the ShareType returned is SMB2_SHARE_TYPE_PRINT (0x03)
     */
    public boolean isPrinterShare() {
        return shareType == 0x03;
    }

    public long getShareFlags() {
        return shareFlags;
    }

    public Set<SMB2ShareCapabilities> getCapabilities() {
        return capabilities;
    }

    public long getMaximalAccess() {
        return maximalAccess;
    }
}
