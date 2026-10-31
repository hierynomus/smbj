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
import com.hierynomus.smbj.connection.OutstandingRequests;
import com.hierynomus.smbj.connection.Request;
import com.hierynomus.smbj.connection.SessionTable;
import com.hierynomus.smbj.connection.Signatory;
import com.hierynomus.smbj.session.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;

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
 * as specified in subsequent sections.&lt;152&gt;
 */
public class SMB2SignatureVerificationPacketHandler extends SMB2PacketHandler {
    private static final Logger logger = LoggerFactory.getLogger(SMB2SignatureVerificationPacketHandler.class);
    private SessionTable sessionTable;
    private Signatory signatory;
    private OutstandingRequests outstandingRequests;

    /**
     * Creates a verifier that trusts the session ID in each response header.
     * @deprecated use {@link #SMB2SignatureVerificationPacketHandler(SessionTable, Signatory, OutstandingRequests)}
     */
    @Deprecated
    public SMB2SignatureVerificationPacketHandler(SessionTable sessionTable, Signatory signatory) {
        this(sessionTable, signatory, null);
    }

    /**
     * Creates a verifier that uses the session, command and signing requirement captured on the outstanding request.
     * @param sessionTable the established sessions
     * @param signatory the signature verifier
     * @param outstandingRequests the requests awaiting responses
     */
    public SMB2SignatureVerificationPacketHandler(SessionTable sessionTable, Signatory signatory, OutstandingRequests outstandingRequests) {
        this.sessionTable = sessionTable;
        this.signatory = signatory;
        this.outstandingRequests = outstandingRequests;
    }

    @Override
    protected void doSMB2Handle(SMB2PacketData packetData) throws TransportException {
        if (isValid(packetData)) {
            next.handle(packetData);
        } else {
            next.handle(new DeadLetterPacketData(packetData.getHeader()));
        }
    }

    boolean isValid(SMB2PacketData packetData) {
        if (packetData.isOplockBreakNotification() || packetData.isDecrypted()) {
            return true;
        }

        long sessionId = packetData.getHeader().getSessionId();
        boolean signingRequired = false;
        if (outstandingRequests != null) {
            Request request = outstandingRequests.getRequestByMessageId(packetData.getSequenceNumber());
            if (request == null) {
                logger.warn("Could not find request for packet {}", packetData);
                return false;
            }
            // Authentication responses are handled by the session builder. Only the request
            // can authorize this exemption, never an untrusted response header.
            if (request.getSessionId() == 0 || request.getCommand() == SMB2_SESSION_SETUP) {
                return true;
            }
            sessionId = request.getSessionId();
            signingRequired = request.isSigningRequired();
        }
        Session session = sessionTable.find(sessionId);

        if (packetData.getHeader().isFlagSet(SMB2_FLAGS_SIGNED)) {
            if (session == null) {
                logger.warn("Could not find session << {} >> for packet {}.", sessionId, packetData);
                return false;
            }
            SecretKey key = session.getSigningKey(packetData.getHeader(), false);
            if (key == null || !signatory.verify(packetData, key)) {
                logger.warn("Invalid packet signature for packet {}", packetData);
                return false;
            }
            logger.debug("Signature for packet {} verified.", packetData);
        } else if (!packetData.isIntermediateAsyncResponse()
            && (signingRequired || session != null && session.isSigningRequired())) {
            logger.warn("Illegal request, session requires message signing, but packet {} is not signed.", packetData);
            return false;
        }
        return true;
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
