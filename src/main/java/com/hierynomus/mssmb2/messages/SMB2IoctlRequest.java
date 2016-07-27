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
package com.hierynomus.mssmb2.messages;

import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2Header;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2Packet;

/**
 * [MS-SMB2].pdf 2.2.31 SMB2 IOCTL Request
 */
public class SMB2IoctlRequest extends SMB2Packet {

    long MAX_OUTPUT_BUFFER_LENGTH = 64 * 1024;

    private final ControlCode controlCode;
    private final SMB2FileId fileId;
    private final byte[] inputData;
    private final boolean fsctl;

    public SMB2IoctlRequest(
        SMB2Dialect negotiatedDialect, long sessionId, long treeId,
        ControlCode controlCode, SMB2FileId fileId,
        byte[] inputData, boolean fsctl
    ) {
        super(57, negotiatedDialect, SMB2MessageCommandCode.SMB2_IOCTL, sessionId, treeId);
        this.controlCode = controlCode;
        this.fileId = fileId;
        this.inputData = inputData == null ? new byte[0] : inputData;
        this.fsctl = fsctl;
    }

    @Override
    protected void writeTo(SMBBuffer smbBuffer) {
        smbBuffer.putUInt16(structureSize); // StructureSize (2 bytes)
        smbBuffer.putReserved2(); // Reserved (2 bytes)
        smbBuffer.putUInt32(controlCode.getValue()); // CtlCode (4 bytes)
        fileId.write(smbBuffer);  // FileId (16 bytes)

        int offset = SMB2Header.STRUCTURE_SIZE + 56;
        if (inputData.length > 0) {
            smbBuffer.putUInt32(offset); // InputOffset (4 bytes)
            smbBuffer.putUInt32(inputData.length); // InputCount (4 bytes)
        } else {
            smbBuffer.putUInt32(0); // InputOffset (4 bytes)
            smbBuffer.putUInt32(0); // InputCount (4 bytes)
        }
        smbBuffer.putUInt32(0); // MaxInputResponse (4 bytes)
        smbBuffer.putUInt32(0); // OutputOffset (4 bytes)
        smbBuffer.putUInt32(0); // OutputCount (4 bytes)
        // TODO 3.3.5.15 Receiving an SMB2 IOCTL Request
        // Spent days on the INVALID_PARAMETER error which turns out
        // due to the validation specified in the above section, but not sure which one.
        // If dialect is 3.x then setting to MAX_OUTPUT_BUFFER_LENGTH works else it fails with INVALID_PARAMETER
        // To make it work in 2.0.2, subtract the (inputdata length + 8).
        smbBuffer.putUInt32(MAX_OUTPUT_BUFFER_LENGTH - (inputData.length + 8)); // MaxOutputResponse (4 bytes)
        smbBuffer.putUInt32(fsctl ? 1 : 0); // Flags (4 bytes)
        smbBuffer.putReserved4(); // Reserved (4 bytes)
        if (inputData.length > 0) {
            smbBuffer.putRawBytes(inputData);
        }
    }

    public enum ControlCode implements EnumWithValue<ControlCode> {
        FSCTL_DFS_GET_REFERRALS(0x00060194L),
        FSCTL_PIPE_PEEK(0x0011400CL),
        FSCTL_PIPE_WAIT(0x00110018L),
        FSCTL_PIPE_TRANSCEIVE(0x0011C017L),
        FSCTL_SRV_COPYCHUNK(0x001440F2L),
        FSCTL_SRV_ENUMERATE_SNAPSHOTS(0x00144064L),
        FSCTL_SRV_REQUEST_RESUME_KEY(0x00140078L),
        FSCTL_SRV_READ_HASH(0x001441bbL),
        FSCTL_SRV_COPYCHUNK_WRITE(0x001480F2L),
        FSCTL_LMR_REQUEST_RESILIENCY(0x001401D4L),
        FSCTL_QUERY_NETWORK_INTERFACE_INFO(0x001401FCL),
        FSCTL_SET_REPARSE_POINT(0x000900A4L),
        FSCTL_DFS_GET_REFERRALS_EX(0x000601B0L),
        FSCTL_FILE_LEVEL_TRIM(0x00098208L),
        FSCTL_VALIDATE_NEGOTIATE_INFO(0x00140204L);

        private long value;

        ControlCode(long value) {
            this.value = value;
        }

        public long getValue() {
            return value;
        }
    }

}
