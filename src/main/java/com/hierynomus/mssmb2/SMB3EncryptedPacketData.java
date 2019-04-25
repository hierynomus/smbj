package com.hierynomus.mssmb2;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBPacketData;

public class SMB3EncryptedPacketData extends SMBPacketData<SMB3EncryptedPacketHeader> {
    public SMB3EncryptedPacketData(byte[] data) throws Buffer.BufferException {
        super(new SMB3EncryptedPacketHeader(), data);
    }

    @Override
    protected void readHeader() throws Buffer.BufferException {

    }
}
