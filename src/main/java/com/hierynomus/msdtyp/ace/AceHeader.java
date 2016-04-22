package com.hierynomus.msdtyp.ace;

import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;

import java.util.EnumSet;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toEnumSet;
import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.valueOf;

public class AceHeader {

    private AceType aceType;
    private EnumSet<AceFlags> aceFlags;
    private int aceSize;

    AceHeader() {
    }

    AceHeader(AceType aceType, EnumSet<AceFlags> aceFlags, int aceSize) {
        this.aceType = aceType;
        this.aceFlags = aceFlags;
        this.aceSize = aceSize;
    }

    public void writeTo(SMBBuffer buffer) {
        buffer.putByte((byte) aceType.getValue());
        buffer.putByte((byte) EnumWithValue.EnumUtils.toLong(aceFlags));
        buffer.putUInt16(aceSize);
    }

    public void readFrom(SMBBuffer buffer) throws Buffer.BufferException {
        this.aceType = valueOf(buffer.readByte(), AceType.class, null);
        this.aceFlags = toEnumSet(buffer.readByte(), AceFlags.class);
        this.aceSize = buffer.readUInt16();
    }

    public int getAceSize() {
        return aceSize;
    }

    void setAceSize(int aceSize) {
        this.aceSize = aceSize;
    }

    @Override
    public String toString() {
        return "AceHeader{" +
                "aceType=" + aceType +
                ", aceFlags=" + aceFlags +
                ", aceSize=" + aceSize +
                '}';
    }
}
