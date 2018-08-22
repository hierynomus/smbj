package com.hierynomus.protocol;

import com.hierynomus.protocol.commons.buffer.Buffer;

/**
 * Represents the received (potentially partially deserialized) packet data.
 * @param <B> The Buffer type.
 */
public interface PacketData<B extends Buffer<B>> {
    B getDataBuffer();
}
