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
package com.hierynomus.smbj.connection;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2GlobalCapability;
import com.hierynomus.mssmb2.SMB3EncryptionCipher;
import com.hierynomus.mssmb2.SMB3HashAlgorithm;
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse;
import com.hierynomus.ntlm.messages.WindowsVersion;
import com.hierynomus.smbj.SmbConfig;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.UUID;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toEnumSet;

public class ConnectionInfo {

    private WindowsVersion windowsVersion;
    private String netBiosName;
    // All SMB2 Dialect
    private byte[] gssNegotiateToken;
    private UUID serverGuid;
    private String serverName;
    private NegotiatedProtocol negotiatedProtocol;
    // SMB 2.1+
    private UUID clientGuid = UUID.randomUUID();
    // For SMB 2.1+ only SMB2_GLOBAL_CAP_LEASING and SMB2_GLOBAL_CAP_LARGE_MTU
    // For SMB 3.x+ all capabilities supported
    private EnumSet<SMB2GlobalCapability> clientCapabilities;
    private EnumSet<SMB2GlobalCapability> serverCapabilities;

    // SMB 3.x+
    private int clientSecurityMode;
    private int serverSecurityMode;
    private String server; // Reference to the server connected to?

    // SMB 3.1.1
    private SMB3HashAlgorithm preauthIntegrityHashId;
    private byte[] preauthIntegrityHashValue;
    private SMB3EncryptionCipher cipherId;
    // How much the SMB server clock is off from client clock
    private Long timeOffsetMillis;


    ConnectionInfo(UUID clientGuid, String serverName, SmbConfig config) {
        // new SessionTable
        // new OutstandingRequests
        this.clientGuid = clientGuid;
        this.gssNegotiateToken = new byte[0];
        this.serverName = serverName;
        this.clientCapabilities = EnumSet.copyOf(config.getClientCapabilities());
    }

    void negotiated(SMBProtocolNegotiator.NegotiationContext negotiationContext) {
//        gssNegotiateToken = response.getGssToken();
        SMB2NegotiateResponse response = negotiationContext.getNegotiationResponse();
        serverGuid = response.getServerGuid();
        serverCapabilities = EnumSet.copyOf(response.getCapabilities());
        this.negotiatedProtocol = new NegotiatedProtocol(response.getDialect(), response.getMaxTransactSize(), response.getMaxReadSize(), response.getMaxWriteSize(), supportsMultiCredit());
        this.serverSecurityMode = response.getSecurityMode();
        this.cipherId = negotiationContext.getCipher();
        this.preauthIntegrityHashId = negotiationContext.getPreauthIntegrityHashId();
        this.preauthIntegrityHashValue = negotiationContext.getPreauthIntegrityHashValue();
        timeOffsetMillis = System.currentTimeMillis() - response.getSystemTime().toEpochMillis();
    }

    public UUID getClientGuid() {
        return clientGuid;
    }

    public boolean isServerRequiresSigning() {
        return (serverSecurityMode & 0x02) > 0;
    }

    public boolean isServerSigningEnabled() {
        return (serverSecurityMode & 0x01) > 0;
    }

    int getServerSecurityMode() {
        return serverSecurityMode;
    }

    EnumSet<SMB2GlobalCapability> getServerCapabilities() {
        return serverCapabilities;
    }

    public NegotiatedProtocol getNegotiatedProtocol() {
        return negotiatedProtocol;
    }

    public byte[] getGssNegotiateToken() {
        return Arrays.copyOf(gssNegotiateToken, gssNegotiateToken.length);
    }

    public UUID getServerGuid() {
        return serverGuid;
    }

    public String getServerName() {
        return serverName;
    }

    public boolean supports(SMB2GlobalCapability capability) {
        return serverCapabilities.contains(capability);
    }

    public EnumSet<SMB2GlobalCapability> getClientCapabilities() {
        return clientCapabilities;
    }

    public WindowsVersion getWindowsVersion() {
        return windowsVersion;
    }

    public void setWindowsVersion(WindowsVersion windowsVersion) {
        this.windowsVersion = windowsVersion;
    }

    public String getNetBiosName() {
        return netBiosName;
    }

    public void setNetBiosName(String netBiosName) {
        this.netBiosName = netBiosName;
    }

    public SMB3EncryptionCipher getCipherId() {
        return cipherId;
    }

    public boolean supportsEncryption() {
        SMB2Dialect dialect = negotiatedProtocol.getDialect();
        if (dialect == SMB2Dialect.SMB_3_1_1) {
            return cipherId != null;
        } else {
            return clientCapabilities.contains(SMB2GlobalCapability.SMB2_GLOBAL_CAP_ENCRYPTION)
                && supports(SMB2GlobalCapability.SMB2_GLOBAL_CAP_ENCRYPTION);
        }
    }

    /**
     * If the client implements SMB 2.1 or SMB 3.x dialect family, the client MUST perform the following:
     * If SMB2_GLOBAL_CAP_LEASING is set in the Capabilities field of the SMB2 NEGOTIATE Response, the client MUST set Connection.SupportsFileLeasing to TRUE. Otherwise, it MUST be set to FALSE.
     * @return
     */
    public boolean supportsFileLeasing() {
        return supports(SMB2GlobalCapability.SMB2_GLOBAL_CAP_LEASING);
    }

    /**
     * If the client implements SMB 2.1 or SMB 3.x dialect family, the client MUST perform the following:
     * If SMB2_GLOBAL_CAP_LARGE_MTU is set in the Capabilities field of the SMB2 NEGOTIATE Response, the client MUST set Connection.SupportsMultiCredit to TRUE. Otherwise, it MUST be set to FALSE.
     * @return
     */
    public boolean supportsMultiCredit() {
        return supports(SMB2GlobalCapability.SMB2_GLOBAL_CAP_LARGE_MTU);
    }

    /**
     * If Connection.Dialect belongs to the SMB 3.x dialect family, the client MUST perform the following:
     * If SMB2_GLOBAL_CAP_DIRECTORY_LEASING is set in the Capabilities field of the SMB2 NEGOTIATE Response, the client MUST set Connection.SupportsDirectoryLeasing to TRUE. Otherwise, it MUST be set to FALSE.
     * @return
     */
    public boolean supportsDirectoryLeasing() {
        return negotiatedProtocol.getDialect().isSmb3x() && supports(SMB2GlobalCapability.SMB2_GLOBAL_CAP_DIRECTORY_LEASING);
    }

    /**
     * If Connection.Dialect belongs to the SMB 3.x dialect family, the client MUST perform the following:
     * If SMB2_GLOBAL_CAP_MULTI_CHANNEL is set in the Capabilities field of the SMB2 NEGOTIATE Response, the client MUST set Connection.SupportsMultiChannel to TRUE. Otherwise, it MUST be set to FALSE.
     * @return
     */
    public boolean supportsMultiChannel() {
        return negotiatedProtocol.getDialect().isSmb3x() && supports(SMB2GlobalCapability.SMB2_GLOBAL_CAP_MULTI_CHANNEL);
    }

    public Long getTimeOffsetMillis() {
        return timeOffsetMillis;
    }

    @Override
    public String toString() {
        return "ConnectionInfo{\n" + "  serverGuid=" + serverGuid + ",\n" +
            "  serverName='" + serverName + "',\n" +
            "  negotiatedProtocol=" + negotiatedProtocol + ",\n" +
            "  clientGuid=" + clientGuid + ",\n" +
            "  clientCapabilities=" + clientCapabilities + ",\n" +
            "  serverCapabilities=" + serverCapabilities + ",\n" +
            "  clientSecurityMode=" + clientSecurityMode + ",\n" +
            "  serverSecurityMode=" + serverSecurityMode + ",\n" +
            "  server='" + server + "'\n" +
            '}';
    }
}
