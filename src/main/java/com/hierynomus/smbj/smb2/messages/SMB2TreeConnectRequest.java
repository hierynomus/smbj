/*
 * Copyright (C)2016 - Jeroen van Erp <jeroen@hierynomus.com>
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

import com.hierynomus.smbj.smb2.SMB2Dialect;
import com.hierynomus.smbj.smb2.SMB2Header;
import com.hierynomus.smbj.smb2.SMB2MessageCommandCode;
import com.hierynomus.smbj.smb2.SMB2Packet;

/**
 * [MS-SMB2].pdf 2.2.9 SMB2 TREE_CONNECT Request
 */
public class SMB2TreeConnectRequest extends SMB2Packet {

    private final SMB2Dialect dialect;
    private boolean isClusterReconnect; // SMB 3.1.1 only
    private String smbPath;

    public SMB2TreeConnectRequest(long messageId, SMB2Dialect dialect) {
        super(messageId, SMB2MessageCommandCode.SMB2_TREE_CONNECT);
        this.dialect = dialect;
    }

    @Override
    protected void writeMessage() {
        putUInt16(9); // StructureSize (2 bytes)
        putFlags(); // Flags (2 bytes)
        putUInt16(SMB2Header.STRUCTURE_SIZE + 9); // PathOffset (2 bytes) (header structure size + msg structure size)
        putUInt16(smbPath.length());
        putString(smbPath);
    }



    private void putFlags() {
        if (dialect == SMB2Dialect.SMB_3_1_1 && isClusterReconnect) {
            putUInt16(0x01);
        } else {
            putReserved(2);
        }
    }
}
