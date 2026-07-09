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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.mssmb2.messages.SMB2LeaseBreakNotification;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.connection.LeaseManager;

/**
 * Intercepts server-pushed SMB2 break notifications (unsolicited, {@code MessageId = 0xFFFF…},
 * command SMB2_OPLOCK_BREAK). A 44-byte lease break is parsed and dispatched OFF the read thread
 * to the {@link LeaseManager}; the packet is then <b>consumed</b> (never forwarded), which avoids
 * the NPE in {@code SMB2AsyncResponsePacketHandler} and the throw in {@code SMB2MessageConverter}
 * that a break would otherwise trigger. Every non-break packet is forwarded unchanged.
 *
 * <p>Inserted right after {@code SMB2IsOutstandingPacketHandler} (which passes the break through
 * rather than dead-lettering it) and before signature verification (the break is unsigned,
 * SessionId 0).
 */
public class SMB2LeaseBreakPacketHandler extends SMB2PacketHandler {
    private static final Logger logger = LoggerFactory.getLogger(SMB2LeaseBreakPacketHandler.class);
    private static final int LEASE_BREAK_NOTIFICATION_SIZE = 44;
    private static final int OPLOCK_BREAK_NOTIFICATION_SIZE = 24;

    private final LeaseManager leaseManager;

    public SMB2LeaseBreakPacketHandler(LeaseManager leaseManager) {
        this.leaseManager = leaseManager;
    }

    @Override
    protected void doSMB2Handle(SMB2PacketData packetData) throws TransportException {
        if (!packetData.isOplockBreakNotification()) {
            next.handle(packetData); // normal responses (incl. our ack's reply) flow on untouched
            return;
        }

        int structureSize = peekStructureSize(packetData);
        if (structureSize != LEASE_BREAK_NOTIFICATION_SIZE) {
            if (structureSize == OPLOCK_BREAK_NOTIFICATION_SIZE) {
                logger.debug("Received oplock break (file oplocks out of scope), ignoring");
            } else {
                logger.warn("Unexpected unsolicited OPLOCK_BREAK StructureSize {}, dropping", structureSize);
            }
            return; // consume
        }

        try {
            SMB2LeaseBreakNotification notification = new SMB2LeaseBreakNotification().parse(packetData);
            logger.debug("Lease break for {} {}->{} ackRequired={}", notification.getLeaseKey(),
                notification.getCurrentLeaseState(), notification.getNewLeaseState(), notification.isAckRequired());
            leaseManager.dispatchBreak(notification); // resolve/ack happens OFF this read thread
        } catch (Buffer.BufferException e) {
            logger.warn("Malformed lease break notification, dropping", e);
        }
        // consume: never call next.handle(...) for a genuine break notification
    }

    private static int peekStructureSize(SMB2PacketData packetData) {
        Buffer<?> buffer = packetData.getDataBuffer();
        int rpos = buffer.rpos();
        try {
            return buffer.readUInt16();
        } catch (Buffer.BufferException e) {
            return -1;
        } finally {
            buffer.rpos(rpos);
        }
    }
}
