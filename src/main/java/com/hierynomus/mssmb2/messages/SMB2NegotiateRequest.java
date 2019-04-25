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
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.negotiate.SMB2EncryptionCapabilities;
import com.hierynomus.mssmb2.messages.negotiate.SMB2NegotiateContext;
import com.hierynomus.mssmb2.messages.negotiate.SMB2PreauthIntegrityCapabilities;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.smb.SMBBuffer;

import java.util.*;

/**
 * [MS-SMB2].pdf 2.2.3 SMB2 Negotiate
 */
public class SMB2NegotiateRequest extends SMB2Packet {

    private Set<SMB2Dialect> dialects;
    private UUID clientGuid;
    private boolean clientSigningRequired;
    private Set<SMB2GlobalCapability> capabilities;
    private List<SMB2NegotiateContext> negotiateContextList;

    /**
     * Request constructor.
     *  @param dialects
     * @param clientGuid
     * @param salt
     */
    public SMB2NegotiateRequest(Set<SMB2Dialect> dialects, UUID clientGuid, boolean clientSigningRequired, Set<SMB2GlobalCapability> capabilities, byte[] salt) {
        super(36, SMB2Dialect.UNKNOWN, SMB2MessageCommandCode.SMB2_NEGOTIATE, 0, 0);
        this.dialects = dialects;
        this.clientGuid = clientGuid;
        this.clientSigningRequired = clientSigningRequired;
        this.capabilities = capabilities;
        this.negotiateContextList = buildNegotiateContextList(salt);
    }

    private List<SMB2NegotiateContext> buildNegotiateContextList(byte[] salt) {
        if (dialects.contains(SMB2Dialect.SMB_3_1_1)) {
            List<SMB2NegotiateContext> contexts = new ArrayList<>();
            List<SMB3HashAlgorithm> hashAlgorithmList = Arrays.asList(SMB3HashAlgorithm.SHA_512);
            contexts.add(new SMB2PreauthIntegrityCapabilities(hashAlgorithmList, salt));
            // [MS-SMB2].pdf <104> Section 3.2.4.2.2.2: Windows 10, Windows Server 2016, and
            // Windows Server operating system initialize with AES-128-GCM(0x0002)
            // followed by AES-128-CCM(0x0001).
            List<SMB3EncryptionCipher> cipherList = Arrays.asList(SMB3EncryptionCipher.AES_128_GCM, SMB3EncryptionCipher.AES_128_CCM);
            contexts.add(new SMB2EncryptionCapabilities(cipherList));
            return contexts;
        }
        return Collections.emptyList();
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
        putCapabilities(buffer); // Capabilities (4 bytes)
        MsDataTypes.putGuid(clientGuid, buffer); // ClientGuid (16 bytes)
        putNegotiateContextOrStartTime(buffer); // (NegotiateContextOffset/NegotiateContextCount/Reserved2)/ClientStartTime (8 bytes)
        putDialects(buffer); // Dialects (x * 2 bytes)
        int eightByteAlignment = (structureSize + dialects.size() * 2) % 8;
        if (eightByteAlignment > 0) {
            buffer.putReserved(8 - eightByteAlignment); // Padding (variable) Ensure that the next field is 8-byte aligned
        }
        putNegotiateContextList(); // NegotiateContextList (variable)
    }

    private int securityMode() {
        if (clientSigningRequired) {
            return 0x02;
        } else {
            return 0x01;
        }
    }

    private void putNegotiateContextList() {
        if (dialects.contains(SMB2Dialect.SMB_3_1_1)) {
            for (int i = 0; i < negotiateContextList.size(); i++) {
                int bytesWritten = negotiateContextList.get(i).write(buffer);
                if (i < negotiateContextList.size() - 1 && bytesWritten % 8 != 0) {
                    // If this wasn't the last SMB2NegotiateContext and not a multiple of 8 bytes written
                    buffer.putReserved(8 - (bytesWritten % 8));
                }
            }
            throw new UnsupportedOperationException("SMB 3.x support is not yet implemented");
        }
    }

    private void putDialects(SMBBuffer buffer) {
        for (SMB2Dialect dialect : dialects) {
            buffer.putUInt16(dialect.getValue()); // Dialect (2 bytes)
        }
    }

    private void putNegotiateContextOrStartTime(SMBBuffer buffer) {
        if (dialects.contains(SMB2Dialect.SMB_3_1_1)) {
            int trueEightByteAlignment = 8 - ((structureSize + dialects.size() * 2) % 8);
            long negotiateContextOffset = SMB2PacketHeader.STRUCTURE_SIZE + structureSize + dialects.size() * 2 + trueEightByteAlignment;
            buffer.putUInt32(negotiateContextOffset); // NegotiateContextOffset (4 bytes)
            buffer.putUInt16(negotiateContextList.size()); // NegotiateContextCount (2 bytes)
            buffer.putReserved2(); // Reserved2 (2 bytes)
        } else {
            // ClientStartTime MUST NOT be used and MUST be reserved. The client MUST set this to 0
            buffer.putReserved(8); // ClientStartTime (8 bytes)
        }
    }

    private void putCapabilities(SMBBuffer buffer) {
        if (SMB2Dialect.supportsSmb3x(dialects)) {
            // If the client implements the SMB 3.x dialect family, the Capabilities field MUST be constructed
            buffer.putUInt32(EnumWithValue.EnumUtils.toLong(capabilities)); // Capabilities (4 bytes)
        } else {
            buffer.putReserved4(); // Capabilities (4 bytes)
        }
    }
}
