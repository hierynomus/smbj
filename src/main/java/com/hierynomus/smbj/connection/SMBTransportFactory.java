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
package com.hierynomus.smbj.connection;

import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.messages.SMB2MessageConverter;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.transport.PacketHandlers;
import com.hierynomus.smbj.transport.PacketReceiver;
import com.hierynomus.smbj.transport.TransportLayer;
import com.hierynomus.smbj.transport.tcp.DirectTcpTransport;

/**
 * Creates an SMB-specific transport layer with the requested mode.
 */
class SMBTransportFactory {
	private static final SMB2MessageConverter converter = new SMB2MessageConverter();

	public TransportLayer<SMB2Packet> createTransportLayer(PacketReceiver<SMB2Packet> receiver, SmbConfig config) {
		switch (config.getTransportMode()) {
		case DIRECT_TCP_SYNC:
			return createDirectTcpSmbTransportLayer(receiver, config);
		default:
			throw new UnsupportedOperationException("Transport mode not supported: " + config.getTransportMode());
		}
	}

	DirectTcpTransport<SMB2Packet> createDirectTcpSmbTransportLayer(PacketReceiver<SMB2Packet> receiver, SmbConfig config) {
		PacketHandlers<SMB2Packet> handlers = new PacketHandlers<>(converter, receiver, converter);
		return new DirectTcpTransport<SMB2Packet>(config.getSocketFactory(), config.getSoTimeout(), handlers);
	}

}
