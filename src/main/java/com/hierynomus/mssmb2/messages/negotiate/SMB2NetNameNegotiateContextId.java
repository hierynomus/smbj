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
package com.hierynomus.mssmb2.messages.negotiate;

import com.hierynomus.protocol.commons.Charsets;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

/**
 * [MS-SMB2].pdf 2.2.3.1.4 / 2.2.4.1.4 SMB2_NETNAME_NEGOTIATE_CONTEXT_ID Request/Response
 */
public class SMB2NetNameNegotiateContextId extends SMB2NegotiateContext {
    private String netName;

    SMB2NetNameNegotiateContextId() {
        super(SMB2NegotiateContextType.SMB2_NETNAME_NEGOTIATE_CONTEXT_ID);
    }

    SMB2NetNameNegotiateContextId(String netName) {
        super(SMB2NegotiateContextType.SMB2_NETNAME_NEGOTIATE_CONTEXT_ID);
        this.netName = netName;

    }

    @Override
    protected int writeContext(SMBBuffer buffer) {
        buffer.putNullTerminatedString(netName, Charsets.UTF_16);
        return netName.length() * 2 + 2;
    }

    @Override
    protected void readContext(SMBBuffer buffer, int dataSize) throws Buffer.BufferException {
        this.netName = buffer.readNullTerminatedString(Charsets.UTF_16);
    }

    public String getNetName() {
        return netName;
    }
}
