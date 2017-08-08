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
package com.hierynomus.ntlm.messages;

import com.hierynomus.protocol.Packet;
import com.hierynomus.protocol.commons.buffer.Buffer;

public class NtlmPacket implements Packet<Buffer.PlainBuffer> {

    @Override
    public void write(Buffer.PlainBuffer buffer) {
        throw new UnsupportedOperationException("Not implemented by base class");
    }

    @Override
    public void read(Buffer.PlainBuffer buffer) throws Buffer.BufferException {
        throw new UnsupportedOperationException("Not implemented by base class");
    }
}
