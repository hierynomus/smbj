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

import com.hierynomus.msdtyp.MsDataTypes;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.smb.SMBBuffer;

import java.util.Set;
import java.util.UUID;

/**
 * [MS-SMB2].pdf 2.2.3 SMB2 Negotiate
 */
public class SMB2NegotiateRequest extends SMB2Packet {

    private Set<SMB2Dialect> dialects;
    private UUID clientGuid;
    private boolean clientSigningRequired;

    /**
     * Request constructor.
     *
     * @param dialects
     * @param clientGuid
     */
    public SMB2NegotiateRequest(Set<SMB2Dialect> dialects, UUID clientGuid, boolean clientSigningRequired) {
        super(36, SMB2Dialect.UNKNOWN, SMB2MessageCommandCode.SMB2_NEGOTIATE, 0, 0);
        this.dialects = dialects;
        this.clientGuid = clientGuid;
        this.clientSigningRequired = clientSigningRequired;
    }

    /**
     * The Request packet
     *
     * @param buffer
     */
    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(structureSize); // StructureSize (2 bytes)
        buffer.putUInt16(dialects.size()); // DialectCount (2 bytes)
        buffer.putUInt16(securityMode()); // SecurityMode (2 bytes)
        buffer.putReserved(2); // Reserved (2 bytes)
        putCapabilities(buffer); // Capabilities (2 bytes)
        MsDataTypes.putGuid(clientGuid, buffer); // ClientGuid (16 bytes)
        putNegotiateStartTime(buffer); // (NegotiateContextOffset/NegotiateContextCount/Reserved2)/ClientStartTime (8 bytes)
        putDialects(buffer); // Dialects (x * 2 bytes)
        int eightByteAlignment = (34 + dialects.size() * 2) % 8;
        if (eightByteAlignment > 0) {
            buffer.putReserved(8 - eightByteAlignment); // Padding (variable) Ensure that the next field is 8-byte aligned
        }
        putNegotiateContextList(); // NegotiateContextList (variable)
    }

    private int securityMode() {
        if (clientSigningRequired) {
            return 0x03;
        } else {
            return 0x01;
        }
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
