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
import com.hierynomus.mssmb2.SMB2GlobalCapability;
import com.hierynomus.mssmb2.SMB2Header;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.Smb2EncryptionCipher;
import com.hierynomus.mssmb2.Smb2HashAlgorithm;
import com.hierynomus.mssmb2.messages.submodule.SMB2EncryptionCapabilitiesRequest;
import com.hierynomus.mssmb2.messages.submodule.SMB2PreauthIntegrityCapabilitiesRequest;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.smb.SMBBuffer;

import java.security.SecureRandom;
import java.util.*;

/**
 * [MS-SMB2].pdf 2.2.3 SMB2 Negotiate
 */
public class SMB2NegotiateRequest extends SMB2Packet {

    public static final int DEFAULT_NEGOTIATE_CONTEXT_COUNT = 2;

    private Set<SMB2Dialect> dialects;
    private UUID clientGuid;
    private boolean clientSigningRequired;
    private Set<SMB2GlobalCapability> clientCapabilities;
    private byte[] salt = null;

    /**
     * Request constructor.
     *
     * @param dialects
     * @param clientGuid
     */
    public SMB2NegotiateRequest(Set<SMB2Dialect> dialects, UUID clientGuid, boolean clientSigningRequired, Set<SMB2GlobalCapability> clientCapabilities) {
        super(36, SMB2Dialect.UNKNOWN, SMB2MessageCommandCode.SMB2_NEGOTIATE, 0, 0);
        this.dialects = dialects;
        this.clientGuid = clientGuid;
        this.clientSigningRequired = clientSigningRequired;
        this.clientCapabilities = clientCapabilities;
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
        putNegotiateStartTime(buffer); // (NegotiateContextOffset/NegotiateContextCount/Reserved2)/ClientStartTime (8 bytes)
        putDialects(buffer); // Dialects (x * 2 bytes)
        int eightByteAlignment = (structureSize + dialects.size() * 2) % 8;
        if (eightByteAlignment > 0) {
            buffer.putReserved(8 - eightByteAlignment); // Padding (variable) Ensure that the next field is 8-byte aligned
        }
        putNegotiateContextList(buffer); // NegotiateContextList (variable)
    }

    private int securityMode() {
        if (clientSigningRequired) {
            return 0x02;
        } else {
            return 0x01;
        }
    }

    private void putNegotiateContextList(SMBBuffer buffer) {
        if (dialects.contains(SMB2Dialect.SMB_3_1_1)) {
            List<Smb2HashAlgorithm> hashAlgorithmList = new ArrayList<>();
            hashAlgorithmList.add(Smb2HashAlgorithm.SHA_512);
            if (this.salt == null) {
                this.salt = initializeSalt(SMB2PreauthIntegrityCapabilitiesRequest.DEFAULT_SALT_LENGTH);
            }
            SMB2PreauthIntegrityCapabilitiesRequest preauthIntegrityCapabilitiesRequest = new SMB2PreauthIntegrityCapabilitiesRequest(hashAlgorithmList, salt);
            preauthIntegrityCapabilitiesRequest.write(buffer);
            List<Smb2EncryptionCipher> cipherList = new ArrayList<>();
            // [MS-SMB2].pdf <104> Section 3.2.4.2.2.2: Windows 10, Windows Server 2016, and
            // Windows Server operating system initialize with AES-128-GCM(0x0002)
            // followed by AES-128-CCM(0x0001).
            cipherList.add(Smb2EncryptionCipher.AES_128_GCM);
            cipherList.add(Smb2EncryptionCipher.AES_128_CCM);
            SMB2EncryptionCapabilitiesRequest
                encryptionCapabilitiesRequest = new SMB2EncryptionCapabilitiesRequest(cipherList);
            encryptionCapabilitiesRequest.write(buffer);
        }
    }

    private void putDialects(SMBBuffer buffer) {
        for (SMB2Dialect dialect : dialects) {
            buffer.putUInt16(dialect.getValue());
        }
    }

    private void putNegotiateStartTime(SMBBuffer buffer) {
        if (dialects.contains(SMB2Dialect.SMB_3_1_1)) {
            // SMB2_PREAUTH_INTEGRITY_CAPABILITIES is always needed for 3.1.1, just depends on encryption support or not.
            int trueEightByteAlignment = 8 - ((structureSize + dialects.size() * 2) % 8);
            long negotiateContextOffset = SMB2Header.STRUCTURE_SIZE + structureSize + dialects.size() * 2 + trueEightByteAlignment;

            // put the values to buffer
            buffer.putUInt32(negotiateContextOffset); // NegotiateContextOffset (4 bytes)
            buffer.putUInt16(DEFAULT_NEGOTIATE_CONTEXT_COUNT); // NegotiateContextCount (2 bytes)
            buffer.putReserved2(); // Reserved2 (2 bytes)
        } else {
            buffer.putReserved4();
            buffer.putReserved4();
        }
    }

    private void putCapabilities(SMBBuffer buffer) {
        if (SMB2Dialect.supportsSmb3x(dialects)) {
            // If the client implements the SMB 3.x dialect family, the Capabilities field MUST be constructed
            buffer.putUInt32(EnumWithValue.EnumUtils.toLong(this.clientCapabilities)); // Capabilities (4 bytes)
        } else {
            // Otherwise, this field MUST be set to 0
            buffer.putReserved4(); // Capabilities (4 bytes)
        }
    }

    private byte[] initializeSalt(int saltLength) {
        byte[] salt = new byte[saltLength];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salt);
        return salt;
    }

}
