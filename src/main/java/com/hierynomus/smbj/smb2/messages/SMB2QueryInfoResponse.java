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
package com.hierynomus.smbj.smb2.messages;

import com.hierynomus.msdtyp.MsDataTypes;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.ntlm.functions.NtlmFunctions;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.smb2.SMB2Packet;
import com.hierynomus.smbj.smb2.SMB2StatusCode;

import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * [MS-SMB2].pdf 2.2.38 SMB2 QUERY_INFO Response
 * <p>
\ */
public class SMB2QueryInfoResponse extends SMB2Packet {

    byte[] outputBuffer;

    public SMB2QueryInfoResponse() {
        super();
    }

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        // TODO how to handle errors correctly
        if (header.getStatus() != SMB2StatusCode.STATUS_SUCCESS) return;

        buffer.skip(2); // StructureSize (2 bytes)
        int outputBufferOffset = buffer.readUInt16(); // Buffer Offset
        long outBufferLength = buffer.readUInt32(); // Buffer length
        outputBuffer = buffer.readRawBytes((int)outBufferLength);
    }

    public byte[] getOutputBuffer() {
        return outputBuffer;
    }
}
