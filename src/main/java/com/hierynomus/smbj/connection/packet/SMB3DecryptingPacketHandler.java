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
package com.hierynomus.smbj.connection.packet;

import com.hierynomus.mssmb2.*;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smb.SMBPacketData;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.connection.PacketEncryptor;
import com.hierynomus.smbj.connection.SessionTable;
import com.hierynomus.smbj.session.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

/**
 * 3.2.5.1.1 Decrypting the Message
 * <p>
 * This section is applicable for only the SMB 3.x dialect family.<149>
 * <p>
 * The client MUST perform the following:
 * <p>
 * If the size of the message received from the server is not greater than the size of SMB2 TRANSFORM_HEADER as
 * specified in section 2.2.41, the client MUST discard the message.
 * <p>
 * If the Flags/EncryptionAlgorithm in the SMB2 TRANSFORM_HEADER is not 0x0001, the client MUST discard the message.
 * <p>
 * The client MUST look up the session in the Connection.SessionTable using the SessionId in the
 * SMB2 TRANSFORM_HEADER of the response. If the session is not found, the response MUST be discarded.
 * <p>
 * The client MUST decrypt the message using Session.DecryptionKey. If Connection.Dialect is "3.1.1", the algorithm
 * specified by Connection.CipherId is used. Otherwise, the AES-128-CCM algorithm is used. The client passes in the
 * Nonce, OriginalMessageSize, Flags/EncryptionAlgorithm, and SessionId fields of the SMB2 TRANSFORM_HEADER and the
 * encrypted SMB2 message as the Optional Authenticated Data input for the algorithm. If decryption succeeds, the
 * client MUST compare the signature in the SMB2 TRANSFORM_HEADER with the signature returned by the decryption
 * algorithm. If signature verification fails, the client MUST fail the application request with an
 * implementation-specific error.
 * <p>
 * If signature verification succeeds, the client MUST perform the following:
 * <ul>
 * <li>If ProtocolId in the header of the decrypted message is 0x424d53FD indicating a nested encrypted message,
 * the client MUST disconnect the connection.</li>
 * <li>If ProtocolId in the header of the decrypted message is 0x424d53FC indicating a nested compressed message,
 * the client MUST decompress the message as specified in section 3.2.5.1.10.
 * <p/>
 * If decompression succeeds, the client MUST further validate the message:
 * <ul>
 * <li>If the NextCommand field in the first SMB2 header of the message is equal to 0 and SessionId of the
 * first SMB2 header is not equal to the SessionId field in SMB2 TRANSFORM_HEADER of response,
 * the client MUST discard the message.</li>
 * <li>For each response in a compounded response, if the SessionId field of SMB2 header is not equal to the
 * SessionId field in the SMB2 TRANSFORM_HEADER, the client SHOULD<150> discard the entire compounded response
 * and stop processing.</li>
 * </ul>
 * </li>
 * <li>If ProtocolId in the header of the decrypted message is 0x424d53FE indicating an SMB2 header, the client
 * MUST further validate the decrypted message:
 * <ul>
 * <li>If the NextCommand field in the first SMB2 header of the message is equal to 0 and SessionId of the
 * first SMB2 header is not equal to the SessionId field in SMB2 TRANSFORM_HEADER of response,
 * the client MUST discard the message.</li>
 * <li>For each response in a compounded response, if the SessionId field of SMB2 header is not equal to the
 * SessionId field in the SMB2 TRANSFORM_HEADER, the client SHOULD<151> discard the entire compounded response
 * and stop processing.</li>
 * </ul>
 * </li>
 * <li>Otherwise, the client MUST disconnect the connection.</li>
 * </ul>
 */
public class SMB3DecryptingPacketHandler extends AbstractIncomingPacketHandler {
    private static final Logger logger = LoggerFactory.getLogger(SMB3DecryptingPacketHandler.class);
    private SMB2Dialect dialect;
    private SessionTable sessionTable;
    private PacketEncryptor encryptor;

    public SMB3DecryptingPacketHandler(SMB2Dialect dialect, SessionTable sessionTable, PacketEncryptor encryptor) {
        this.dialect = dialect;
        this.sessionTable = sessionTable;
        this.encryptor = encryptor;
    }

    @Override
    protected boolean canHandle(SMBPacketData<?> packetData) {
        return packetData instanceof SMB3EncryptedPacketData;
    }

    @Override
    protected void doHandle(SMBPacketData<?> packetData) throws TransportException {
        SMB3EncryptedPacketData data = (SMB3EncryptedPacketData) packetData;
        logger.info("Decrypting packet {}", data);

        if (!dialect.isSmb3x()
            || data.getDataBuffer().available() == 0 // SMBPacketData eagerly reads the header, so if no data left, fail.
            || data.getHeader().getFlagsEncryptionAlgorithm() != 0x01) {
            next.handle(new DeadLetterPacketData(packetData.getHeader()));
            return;
        }

        long sessionId = data.getHeader().getSessionId();
        Session session = sessionTable.find(sessionId);
        if (session == null) {
            next.handle(new DeadLetterPacketData(packetData.getHeader()));
            return;
        }

        byte[] encryptionKey = null;
        byte[] decrypted = encryptor.decrypt(data, encryptionKey);

        byte[] decryptedProtocolId = Arrays.copyOf(decrypted, 4);
        if (Arrays.equals(decryptedProtocolId, SMB2TransformHeader.ENCRYPTED_PROTOCOL_ID)) {
            logger.error("Encountered a nested encrypted packet in packet {}, disconnecting the transport", packetData);
            throw new TransportException("Cannot nest an encrypted packet in encrypted packet " + packetData);
        } else if (Arrays.equals(decryptedProtocolId, SMB2CompressionTransformHeader.COMPRESSED_PROTOCOL_ID)) {
            handleCompressedPacket(packetData, decrypted);
            return;
        } else if (Arrays.equals(decryptedProtocolId, SMB2PacketHeader.PROTOCOL_ID)) {
            handleSMB2Packet(decrypted, data);
            return;
        } else {
            logger.error("Could not determine the encrypted packet contents of packet {}", packetData);
            throw new TransportException("Could not determine the encrypted packet data, disconnecting");
        }
    }

    private void handleCompressedPacket(SMBPacketData<?> packetData, byte[] decrypted) throws TransportException {
        logger.debug("Decrypted packet {} is compresed.", packetData);
        try {
            next.handle(new SMB3CompressedPacketData(decrypted));
            // TODO not handling further decompression validation
            return;
        } catch (Buffer.BufferException e) {
            throw new SMBRuntimeException("Could not load compression header", e);
        }
    }

    private void handleSMB2Packet(byte[] decrypted, SMB3EncryptedPacketData packetData) throws TransportException {
        try {
            logger.debug("Descrypted packet {} is a regular packet.", packetData);
            SMB2PacketData nextPacket = new SMB2PacketData(decrypted);
            if (nextPacket.getHeader().getSessionId() != packetData.getHeader().getSessionId()) {
                next.handle(new DeadLetterPacketData(nextPacket.getHeader()));
            } else {
                next.handle(nextPacket);
                // TODO handle compounded session id validation...
            }
        } catch (Buffer.BufferException e) {
            throw new SMBRuntimeException("Could not load SMB2 Packet", e);
        }
    }

}
