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

import com.hierynomus.ntlm.functions.NtlmFunctions;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.smb2.*;

/**
 * [MS-SMB2].pdf 2.2.9 SMB2 TREE_CONNECT Request
 */
public class SMB2TreeConnectRequest extends SMB2Packet {

    private final SMB2Dialect dialect;
    private boolean isClusterReconnect; // SMB 3.1.1 only
    private String smbPath;

    public SMB2TreeConnectRequest(SMB2Dialect dialect, String smbPath, long sessionId) {
        super(9, dialect, SMB2MessageCommandCode.SMB2_TREE_CONNECT, sessionId, 0);
        this.dialect = dialect;
        this.smbPath = smbPath;
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(structureSize); // StructureSize (2 bytes)
        putFlags(buffer); // Flags (2 bytes)
        buffer.putUInt16(SMB2Header.STRUCTURE_SIZE + 8); // PathOffset (2 bytes) (header structure size + msg structure size)
        buffer.putStringLengthUInt16(smbPath); // PathLength (2 bytes)
        buffer.putString(smbPath); // Buffer (variable)
    }

    private void putFlags(SMBBuffer buffer) {
        if (dialect == SMB2Dialect.SMB_3_1_1 && isClusterReconnect) {
            buffer.putUInt16(0x01);
        } else {
            buffer.putReserved2();
        }
    }
}
