package com.hierynomus.mssmb2;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBPacketData;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.isSet;

/**
 * Represents the partially deserialized SMB2Packet contents.
 * <p>
 * The SMB2 Header is always present and has a fixed layout. The packet data itself varies based on the {@link SMB2MessageCommandCode} in the header,
 * together with the {@link com.hierynomus.mserref.NtStatus}.
 */
public class SMB2PacketData extends SMBPacketData<SMB2Header> {

    public SMB2PacketData(byte[] data) throws Buffer.BufferException {
        super(new SMB2Header(), data);
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
}
