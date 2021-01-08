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
import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.connection.PacketSignatory;
import com.hierynomus.smbj.connection.SessionTable;
import com.hierynomus.smbj.session.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.hierynomus.mssmb2.SMB2MessageCommandCode.SMB2_SESSION_SETUP;
import static com.hierynomus.mssmb2.SMB2MessageFlag.SMB2_FLAGS_SIGNED;

/**
 * 3.2.5.1.3 Verifying the Signature
 * If the client implements the SMB 3.x dialect family and if the decryption in section 3.2.5.1.1 succeeds,
 * the client MUST skip the processing in this section.
 * <p>
 * If the MessageId is 0xFFFFFFFFFFFFFFFF, no verification is necessary.
 * <p>
 * If the SMB2 header of the response has SMB2_FLAGS_SIGNED set in the Flags field and the message is not encrypted,
 * the client MUST verify the signature as follows:
 * <p>
 * The client MUST look up the session in the Connection.SessionTable using the SessionId in the SMB2 header
 * of the response. If the session is not found, the response MUST be discarded as invalid.
 * <p>
 * If Connection.Dialect belongs to the SMB 3.x dialect family, and the received message is an SMB2 SESSION_SETUP
 * Response without a status code equal to STATUS_SUCCESS in the header, the client MUST verify the signature of
 * the message as specified in section 3.1.5.1, using Session.SigningKey as the signing key, and passing the response
 * message. For all other messages, the client MUST look up the Channel in Session.ChannelList, where the
 * Channel.Connection matches the connection on which this message is received, and MUST use Channel.SigningKey
 * for verifying the signature as specified in section 3.1.5.1.
 * <p>
 * Otherwise, the client MUST verify the signature of the message as specified in section 3.1.5.1, using
 * Session.SessionKey as the signing key, and passing the response message.
 * <p>
 * If signature verification fails, the client MUST discard the received message and do no further processing for it.
 * The client MAY also choose to disconnect the connection. If signature verification succeeds, the client MUST
 * continue processing the packet, as specified in subsequent sections.
 * <p>
 * If the SMB2 header of the response does not have SMB2_FLAGS_SIGNED set in the Flags field, the client MUST
 * determine if the server failed to sign a packet that required signing. If the message is an interim response
 * or an SMB2 OPLOCK_BREAK notification, signing validation MUST NOT occur. Otherwise, the client MUST look up
 * the session in the Connection.SessionTable using the SessionId in the SMB2 header of the response. If the session
 * is found, the Session.SigningRequired is equal to TRUE, the message is not an interim response, and the message
 * is not an SMB2 OPLOCK_BREAK notification, the client MUST discard the received message and do no further
 * processing for it. The client MAY also choose to disconnect the connection. If there is no SessionId, if the
 * session is not found, or if Session.SigningRequired is FALSE, the client continues processing on the packet,
 * as specified in subsequent sections.<152>
 */
public class SMB2SignatureVerificationPacketHandler extends SMB2PacketHandler {
    private static final Logger logger = LoggerFactory.getLogger(SMB2SignatureVerificationPacketHandler.class);
    private SessionTable sessionTable;
    private PacketSignatory signatory;

    public SMB2SignatureVerificationPacketHandler(SessionTable sessionTable, PacketSignatory signatory) {
        this.sessionTable = sessionTable;
        this.signatory = signatory;
    }

    @Override
    protected void doSMB2Handle(SMB2PacketData packetData) throws TransportException {
        if (packetData.getHeader().getMessageId() == 0xFFFFFFFFFFFFFFFFL) {
            logger.debug("Message ID is 0xFFFFFFFFFFFFFFFF, no verification necessary");
            next.handle(packetData);
            return;
        }

        if (packetData.isDecrypted()) {
            logger.debug("Passthrough Signature Verification as packet is decrypted");
            next.handle(packetData);
            return;
        }

        if (packetData.getHeader().isFlagSet(SMB2_FLAGS_SIGNED)) {
            long sessionId = packetData.getHeader().getSessionId();
            // TODO Deviation from Spec...
            if (sessionId == 0L || packetData.getHeader().getMessage() == SMB2_SESSION_SETUP) {
                next.handle(packetData);
                return;
            }
            Session session = sessionTable.find(sessionId);

            if (session == null) {
                logger.error("Could not find session << {} >> for packet {}.", sessionId, packetData);
                next.handle(new DeadLetterPacketData(packetData.getHeader()));
                return;
            }

            if (signatory.verify(packetData, session.getSigningKey(packetData.getHeader(), false))) {
                logger.debug("Signature for packet {} verified.", packetData);
                next.handle(packetData);
                return;
            } else {
                logger.warn("Invalid packet signature for packet {}", packetData);
                next.handle(new DeadLetterPacketData(packetData.getHeader()));
                return;
            }
        }

        if (!packetData.getHeader().isFlagSet(SMB2_FLAGS_SIGNED)) {
            if (packetData.isIntermediateAsyncResponse() || packetData.isOplockBreakNotification()) {
                // ok
            } else {
                long sessionId = packetData.getHeader().getSessionId();
                Session session = sessionTable.find(sessionId);
                if (session != null && session.isSigningRequired()) {
                    logger.warn("Illegal request, session requires message signing, but packet {} is not signed.", packetData);
                    next.handle(new DeadLetterPacketData(packetData.getHeader()));
                    return;
                }
            }
        }
        next.handle(packetData);
    }
//
//    private void verifyPacketSignature(SMB2Packet packet, Session session) throws TransportException {
//        if (!session.getPacketSignatory().verify(packet)) {
//            logger.warn("Invalid packet signature for packet {}", packet);
//            if (session.isSigningRequired()) {
//                throw new TransportException("Packet signature for packet " + packet + " was not correct");
//            }
//        }
//    } else if(session.isSigningRequired())
//
//    {
//        logger.warn("Illegal request, session requires message signing, but packet {} is not signed.", packet);
//        throw new TransportException("Session requires signing, but packet " + packet + " was not signed");
//    }
//}


}
