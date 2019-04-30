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

import com.hierynomus.mssmb2.DeadLetterPacketData;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB3EncryptedPacketData;
import com.hierynomus.protocol.PacketData;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smb.SMBPacketData;

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
    private SMB2Dialect dialect;

    public SMB3DecryptingPacketHandler(SMB2Dialect dialect) {
        this.dialect = dialect;
    }

    @Override
    protected boolean canHandle(SMBPacketData<?> packetData) {
        return packetData instanceof SMB3EncryptedPacketData;
    }

    @Override
    protected void doHandle(SMBPacketData<?> packetData) throws TransportException {
        if (!dialect.isSmb3x()) {
            next.handle(new DeadLetterPacketData(packetData.getHeader()));
            return;
        }


    }
}
