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
package com.hierynomus.mssmb2;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smb.SMBPacketData;

import static com.hierynomus.mssmb2.SMB2MessageCommandCode.SMB2_OPLOCK_BREAK;
import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.isSet;

/**
 * Represents the partially deserialized SMB2Packet contents.
 * <p>
 * The SMB2 Header is always present and has a fixed layout. The packet data itself varies based on the {@link SMB2MessageCommandCode} in the header,
 * together with the {@link com.hierynomus.mserref.NtStatus}.
 */
public class SMB2PacketData extends SMBPacketData<SMB2PacketHeader> {

    public SMB2PacketData(byte[] data) throws Buffer.BufferException {
        super(new SMB2PacketHeader(), data);
    }

    SMB2PacketData(SMBBuffer buffer) throws Buffer.BufferException {
        super(new SMB2PacketHeader(), buffer);
    }

    public long getSequenceNumber() {
        return getHeader().getMessageId();
    }

    /**
     * Check whether this packetData has an  {@link NtStatus#isSuccess() success} status
     * @return
     */
    protected boolean isSuccess() {
        long statusCode = getHeader().getStatusCode();
        return NtStatus.isSuccess(statusCode) && statusCode != NtStatus.STATUS_PENDING.getValue();
    }

    /**
     * Check whether this packet is an intermediate ASYNC response
     */
    public boolean isIntermediateAsyncResponse() {
        return isSet(getHeader().getFlags(), SMB2MessageFlag.SMB2_FLAGS_ASYNC_COMMAND) && getHeader().getStatusCode() == NtStatus.STATUS_PENDING.getValue();
    }

    /**
     * Check whether this is an SMB2_OPLOCK_BREAK Notification packet
     */
    public boolean isOplockBreakNotification() {
        return getHeader().getMessageId() == 0xFFFFFFFFFFFFFFFFL && getHeader().getMessage() == SMB2_OPLOCK_BREAK;
    }


    /**
     * Check whether this Packet is part of a Compounded message
     * @return
     */
    public boolean isCompounded() {
        return getHeader().getNextCommandOffset() != 0;
    }

    public SMB2PacketData next() throws Buffer.BufferException {
        if (isCompounded()) {
            return new SMB2PacketData(dataBuffer);
        } else {
            return null;
        }
    }

    public boolean isDecrypted() {
        return false;
    }

    @Override
    public String toString() {
        return getHeader().getMessage() + " with message id << " + getHeader().getMessageId() + " >>";
    }
}
