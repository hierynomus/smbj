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
package com.hierynomus.protocol.transport;

import com.hierynomus.protocol.Packet;

/**
 * Groups together all the various handlers involved in dealing with packets of
 * type P.
 */
public class PacketHandlers<P extends Packet<?>> {
    private final PacketSerializer<P, ?> serializer;
    private final PacketReceiver<P> receiver;
    private final PacketFactory<P> packetFactory;

    public PacketHandlers(PacketSerializer<P, ?> serializer, PacketReceiver<P> receiver, PacketFactory<P> packetFactory) {
        super();
        this.serializer = serializer;
        this.receiver = receiver;
        this.packetFactory = packetFactory;
    }

    public PacketSerializer<P, ?> getSerializer() {
        return serializer;
    }

    public PacketReceiver<P> getReceiver() {
        return receiver;
    }

    public PacketFactory<P> getPacketFactory() {
        return packetFactory;
    }

}
