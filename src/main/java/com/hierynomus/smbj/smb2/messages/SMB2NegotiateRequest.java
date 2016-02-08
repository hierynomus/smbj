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

import com.hierynomus.smbj.common.SMBBuffer;
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
     * @param dialects
     * @param clientGuid
     */
    public SMB2NegotiateRequest(EnumSet<SMB2Dialect> dialects, UUID clientGuid) {
        super(SMB2MessageCommandCode.SMB2_NEGOTIATE);
        header.setDialect(SMB2Dialect.UNKNOWN);
        header.setCreditCost(0);
        header.setTreeId(0);
        header.setSessionId(0);
        this.dialects = dialects;
        this.clientGuid = clientGuid;
    }

    /**
     * The Request packet
     * @param buffer
     */
    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(36); // StructureSize (2 bytes)
        buffer.putUInt16(dialects.size()); // DialectCount (2 bytes)
        buffer.putUInt16(1); // SecurityMode (2 bytes) Hardcoded to enabled.
        buffer.putReserved(2); // Reserved (2 bytes)
        putCapabilities(buffer); // Capabilities (2 bytes)
        buffer.putGuid(clientGuid); // ClientGuid (16 bytes)
        putNegotiateStartTime(buffer); // (NegotiateContextOffset/NegotiateContextCount/Reserved2)/ClientStartTime (8 bytes)
        putDialects(buffer); // Dialects (x * 2 bytes)
        int eightByteAlignment = (34 + dialects.size() * 2) % 8;
        if (eightByteAlignment > 0) {
            buffer.putReserved(8 - eightByteAlignment); // Padding (variable) Ensure that the next field is 8-byte aligned
        }
        putNegotiateContextList(); // NegotiateContextList (variable)
    }

    private void putNegotiateContextList() {
        if (dialects.contains(SMB2Dialect.SMB_3_1_1)) {
            throw new UnsupportedOperationException("SMB 3.x support is not yet implemented");
        }
    }

    private void putDialects(SMBBuffer buffer) {
        for (SMB2Dialect dialect : dialects) {
            buffer.putUInt16(dialect.getValue());
        }
    }

    private void putNegotiateStartTime(SMBBuffer buffer) {
        if (dialects.contains(SMB2Dialect.SMB_3_1_1)) {
            throw new UnsupportedOperationException("SMB 3.x support is not yet implemented");
        } else {
            buffer.putReserved4();
            buffer.putReserved4();
        }
    }

    private void putCapabilities(SMBBuffer buffer) {
        if (SMB2Dialect.supportsSmb3x(dialects)) {
            throw new UnsupportedOperationException("SMB 3.x support is not yet implemented");
        } else {
            buffer.putReserved4();
        }
    }
}
