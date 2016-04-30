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
package com.hierynomus.smbj.smb2.messages;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.smb2.SMB2Packet;
import com.hierynomus.mserref.NtStatus;

/**
 * [MS-SMB2].pdf 2.2.10 SMB2 TREE_CONNECT Response
 *
 * TODO
 */
public class SMB2TreeConnectResponse extends SMB2Packet {

    private byte shareType;
    private long shareFlags;
    private long capabilities;
    private long maximalAccess;

    public SMB2TreeConnectResponse() {
            super();
    }


    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        if (header.getStatus() == NtStatus.STATUS_SUCCESS) {
            buffer.skip(2); // StructureSize (2 bytes)
            shareType = buffer.readByte(); // ShareType (1 byte)
            buffer.readByte(); // Reserved (1 byte)
            shareFlags = buffer.readUInt32(); // ShareFlags (4 bytes)
            capabilities = buffer.readUInt32(); // Capabilities (4 bytes)
            maximalAccess = buffer.readUInt32(); // MaximalAccess (4 bytes)
        }
    }

    public byte getShareType() {
        return shareType;
    }

    public long getShareFlags() {
        return shareFlags;
    }

    public long getCapabilities() {
        return capabilities;
    }

    public long getMaximalAccess() {
        return maximalAccess;
    }
}
