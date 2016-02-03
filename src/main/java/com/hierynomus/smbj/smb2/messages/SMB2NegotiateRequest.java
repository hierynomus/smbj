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
import com.hierynomus.smbj.smb2.SMB2MessageCommandCode;
import com.hierynomus.smbj.smb2.SMB2Packet;

import java.util.EnumSet;
import java.util.UUID;

/**
 * [MS-SMB2].pdf 2.2.3 SMB2 Negotiate
 */
public class SMB2NegotiateRequest extends SMB2Packet {

    private EnumSet<SMB2Dialect> dialects;
    private UUID clientGuid;

    /**
     * Request constructor.
     * @param messageId
     * @param dialects
     * @param clientGuid
     */
    public SMB2NegotiateRequest(long messageId, EnumSet<SMB2Dialect> dialects, UUID clientGuid) {
        super(messageId, SMB2MessageCommandCode.SMB2_NEGOTIATE);
        header.setDialect(SMB2Dialect.UNKNOWN);
        header.setCreditCost(0);
        header.setTreeId(0);
        header.setSessionId(0);
        this.dialects = dialects;
        this.clientGuid = clientGuid;
    }

    /**
     * The Request packet
     */
    @Override
    protected void writeMessage() {
        putUInt16(36); // StructureSize (2 bytes)
        putUInt16(dialects.size()); // DialectCount (2 bytes)
        putUInt16(1); // SecurityMode (2 bytes) Hardcoded to enabled.
        putReserved(2); // Reserved (2 bytes)
        putCapabilities(); // Capabilities (2 bytes)
        putGuid(clientGuid); // ClientGuid (16 bytes)
        putNegotiateStartTime(); // (NegotiateContextOffset/NegotiateContextCount/Reserved2)/ClientStartTime (8 bytes)
        putDialects(); // Dialects (x * 2 bytes)
        int eightByteAlignment = (34 + dialects.size() * 2) % 8;
        if (eightByteAlignment > 0) {
            putReserved(8 - eightByteAlignment); // Padding (variable) Ensure that the next field is 8-byte aligned
        }
        putNegotiateContextList(); // NegotiateContextList (variable)
    }

    private void putNegotiateContextList() {
        if (dialects.contains(SMB2Dialect.SMB_3_1_1)) {
            throw new UnsupportedOperationException("SMB 3.x support is not yet implemented");
        }
    }

    private void putDialects() {
        for (SMB2Dialect dialect : dialects) {
            putUInt16(dialect.getValue());
        }
    }

    private void putNegotiateStartTime() {
        if (dialects.contains(SMB2Dialect.SMB_3_1_1)) {
            throw new UnsupportedOperationException("SMB 3.x support is not yet implemented");
        } else {
            putReserved4();
            putReserved4();
        }
    }

    private void putCapabilities() {
        if (SMB2Dialect.supportsSmb3x(dialects)) {
            throw new UnsupportedOperationException("SMB 3.x support is not yet implemented");
        } else {
            putReserved4();
        }
    }
}
