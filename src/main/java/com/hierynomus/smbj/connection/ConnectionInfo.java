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
import com.hierynomus.mssmb2.Smb2EncryptionCipher;
import com.hierynomus.mssmb2.Smb2HashAlgorithm;
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse;
import com.hierynomus.mssmb2.messages.submodule.SMB2EncryptionCapabilitiesResponse;
import com.hierynomus.mssmb2.messages.submodule.SMB2NegotiateContext;
import com.hierynomus.mssmb2.messages.submodule.SMB2PreauthIntegrityCapabilitiesResponse;
import com.hierynomus.ntlm.messages.WindowsVersion;
import com.hierynomus.security.MessageDigest;
import com.hierynomus.security.SecurityException;
import com.hierynomus.smb.SMBPacket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toEnumSet;
import static com.hierynomus.security.DigestUtil.concatenatePreviousUpdateDigest;
import static com.hierynomus.security.DigestUtil.getRequestPacketBytes;
import static com.hierynomus.security.DigestUtil.getResponsePacketBytes;

public class ConnectionInfo {

    // the corresponding connection
    private final Connection connection;
    private static final Logger logger = LoggerFactory.getLogger(ConnectionInfo.class);

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
    private Smb2EncryptionCipher cipherId = null;
    // SMB 3.1.1
    private Smb2HashAlgorithm preauthIntegrityHashId = null;
    private byte[] preauthIntegrityHashValue = null;

    ConnectionInfo(Connection connection, UUID clientGuid, String serverName, Set<SMB2GlobalCapability> clientCapabilities) {
        // new SessionTable
        // new OutstandingRequests
        this.connection = connection;
        this.clientGuid = clientGuid;
        this.gssNegotiateToken = new byte[0];
        this.serverName = serverName;
        this.clientCapabilities = EnumSet.copyOf(clientCapabilities);
    }

    void negotiated(SMBPacket negotiateRequest, SMB2NegotiateResponse response) {
//        gssNegotiateToken = response.getGssToken();
        serverGuid = response.getServerGuid();
        serverCapabilities = toEnumSet(response.getCapabilities(), SMB2GlobalCapability.class);
        this.negotiatedProtocol = new NegotiatedProtocol(response.getDialect(), response.getMaxTransactSize(), response.getMaxReadSize(), response.getMaxWriteSize(), serverCapabilities.contains(SMB2GlobalCapability.SMB2_GLOBAL_CAP_LARGE_MTU));
        serverSecurityMode = response.getSecurityMode();

        // if dialect is 3.1.1, read the NegotiateContextList. Otherwise, using the default.
        if (negotiatedProtocol.getDialect() == SMB2Dialect.SMB_3_1_1) {
            List<SMB2NegotiateContext> negotiateContextList = response.getNegotiateContextList();
            if (negotiateContextList != null) {
                for (SMB2NegotiateContext negotiateContext: negotiateContextList) {
                    switch (negotiateContext.getNegotiateContextType()) {
                        case SMB2_PREAUTH_INTEGRITY_CAPABILITIES: {
                            SMB2PreauthIntegrityCapabilitiesResponse
                                preauthIntegrityCapabilitiesResponse = (SMB2PreauthIntegrityCapabilitiesResponse) negotiateContext;

                            // get the requestBytes and responseBytes
                            byte[] requestBytes = getRequestPacketBytes(negotiateRequest);
                            byte[] responseBytes = getResponsePacketBytes(response);

                            this.preauthIntegrityHashId = preauthIntegrityCapabilitiesResponse.getHashAlgorithm();

                            if (this.preauthIntegrityHashId == null) {
                                logger.error("Unable to read preauthIntegrityHashId from negotiate response.");
                                throw new IllegalStateException("Unable to read preauthIntegrityHashId from negotiate response.");
                            }

                            try {
                                // initialize with zero (length is depends on the digest algorithm)
                                this.preauthIntegrityHashValue = initializePreauthIntegrityHashValue();
                                // concatenating the initial value and negotiateRequestBytes then digest
                                this.preauthIntegrityHashValue = internalUpdateDigest(requestBytes);
                                // concatenating the previous value and negotiateResponseBytes then digest
                                this.preauthIntegrityHashValue = internalUpdateDigest(responseBytes);
                            } catch (SecurityException e) {
                                logger.error("Unable to updatePreauthIntegrityHashValue cause by SecurityException, ", e);
                                throw new IllegalStateException("Unable to updatePreauthIntegrityHashValue cause by SecurityException", e);
                            }

                            break;
                        }
                        case SMB2_ENCRYPTION_CAPABILITIES: {
                            SMB2EncryptionCapabilitiesResponse
                                encryptionCapabilitiesResponse = (SMB2EncryptionCapabilitiesResponse)negotiateContext;
                            this.cipherId = encryptionCapabilitiesResponse.getEncryptionCipher();
                            break;
                        }
                        default:
                            throw new IllegalStateException("unknown negotiate context type");
                    }
                }
            } else {
                throw new IllegalStateException("negotiate context list is null for SMB 3.1.1 dialect");
            }
        } else {
            // Set the cipherId for SMB 3.0.x dialect.
            if (negotiatedProtocol.getDialect().isSmb3x()) {
                cipherId = Smb2EncryptionCipher.AES_128_CCM;
            }
        }
    }

    private byte[] initializePreauthIntegrityHashValue() throws SecurityException {
        if (preauthIntegrityHashId == null) {
            logger.error("Unable to initializePreauthIntegrityHashValue as preauthIntegrityHashId is null");
            throw new IllegalStateException("Unable to initializePreauthIntegrityHashValue as preauthIntegrityHashId is null");
        }

        MessageDigest messageDigest =
            connection.getConfig().getSecurityProvider().getDigest(preauthIntegrityHashId.getAlgorithmName());
        // 3.2.5.2 Receiving an SMB2 NEGOTIATE Response, client MUST initialize Connection.PreauthIntegrityHashValue with zero
        return new byte[messageDigest.getDigestLength()];
    }

    private byte[] internalUpdateDigest(byte[] updateBytes) throws SecurityException {
        if (preauthIntegrityHashId == null) {
            logger.error("Unable to updatePreauthIntegrityHashValue as preauthIntegrityHashId is null");
            throw new IllegalStateException("Unable to updatePreauthIntegrityHashValue as preauthIntegrityHashId is null");
        }
        if (preauthIntegrityHashValue == null) {
            logger.error("Unable to updatePreauthIntegrityHashValue as previous preauthIntegrityHashValue is null");
            throw new IllegalStateException("Unable to updatePreauthIntegrityHashValue as previous preauthIntegrityHashValue is null");
        }

        MessageDigest messageDigest =
            connection.getConfig().getSecurityProvider().getDigest(preauthIntegrityHashId.getAlgorithmName());

        return concatenatePreviousUpdateDigest(messageDigest, this.preauthIntegrityHashValue, updateBytes);
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

    public Smb2HashAlgorithm getPreauthIntegrityHashId() {
        return preauthIntegrityHashId;
    }

    public byte[] getPreauthIntegrityHashValue() {
        return preauthIntegrityHashValue;
    }

    public Smb2EncryptionCipher getEncryptionCipher() {
        return cipherId;
    }

    public boolean isConnectionSupportEncrypt() {
        SMB2Dialect dialect = negotiatedProtocol.getDialect();
        boolean supportEncrypt = false;
        if(dialect == SMB2Dialect.SMB_3_1_1) {
            supportEncrypt = cipherId != null;
        } else {
            // if both the client and server support encrypt, return true
            supportEncrypt = clientCapabilities.contains(SMB2GlobalCapability.SMB2_GLOBAL_CAP_ENCRYPTION)
                             && supports(SMB2GlobalCapability.SMB2_GLOBAL_CAP_ENCRYPTION);
        }

        return supportEncrypt;
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
