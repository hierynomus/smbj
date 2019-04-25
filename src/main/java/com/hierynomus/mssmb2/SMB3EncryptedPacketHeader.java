package com.hierynomus.mssmb2;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smb.SMBHeader;

public class SMB3EncryptedPacketHeader implements SMBHeader {
    @Override
    public void writeTo(SMBBuffer buffer) {

    }

    @Override
    public void readFrom(Buffer<?> buffer) throws Buffer.BufferException {

    }

    @Override
    public int getHeaderStartPosition() {
        return 0;
    }
}
