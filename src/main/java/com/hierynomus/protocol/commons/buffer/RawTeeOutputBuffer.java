package com.hierynomus.protocol.commons.buffer;

public class RawTeeOutputBuffer implements RawOutputBuffer<RawTeeOutputBuffer> {
    private RawOutputBuffer<?> first;
    private RawOutputBuffer<?> tee;

    public RawTeeOutputBuffer(RawOutputBuffer<?> first, RawOutputBuffer<?> tee) {
        this.first = first;
        this.tee = tee;
    }

    @Override
    public int wpos() {
        return first.wpos();
    }

    @Override
    public void clear() {
        first.clear();
        tee.clear();
    }

    @Override
    public RawOutputBuffer<RawTeeOutputBuffer> putByte(byte b) {
        first.putByte(b);
        tee.putByte(b);
        return this;
    }

    @Override
    public RawOutputBuffer<RawTeeOutputBuffer> putRawBytes(byte[] buf) {
        first.putRawBytes(buf);
        tee.putRawBytes(buf);
        return this;
    }

    @Override
    public RawOutputBuffer<RawTeeOutputBuffer> putRawBytes(byte[] buf, int offset, int length) {
        first.putRawBytes(buf, offset, length);
        tee.putRawBytes(buf, offset, length);
        return this;
    }
}
