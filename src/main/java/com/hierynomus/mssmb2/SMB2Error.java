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
package com.hierynomus.mssmb2;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.protocol.commons.Charsets;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

import java.util.ArrayList;
import java.util.List;

/**
 * [MS-SMB2] 2.2.2 SMB2 ERROR Response
 */
public class SMB2Error {

    private List<SMB2ErrorData> errorData = new ArrayList<>();

    SMB2Error() {
    }

    SMB2Error read(SMB2PacketHeader header, SMBBuffer buffer) throws Buffer.BufferException {
        buffer.skip(2); // StructureSize (2 bytes)
        int errorContextCount = buffer.readByte(); // ErrorContextCount (1 byte)
        buffer.skip(1); // Reserved (1 byte)
        int byteCount = buffer.readUInt32AsInt(); // ByteCount (4 bytes)

        if (errorContextCount > 0) {
            readErrorContext(header, buffer, errorContextCount);
        } else if (byteCount > 0) {
            readErrorData(header, buffer);
        } else if (byteCount == 0) {
            // Win10 1709 does not provide ErrorData
            if (buffer.available() > 0) {
                buffer.skip(1); // ErrorData (1 byte)
            }
        }

        return this;
    }

    /**
     * [MS-SMB2] 2.2.2.1 SMB2 ERROR Context Response
     *
     * @param header
     * @param buffer
     * @param errorContextCount
     * @throws Buffer.BufferException
     */
    private void readErrorContext(SMB2PacketHeader header, SMBBuffer buffer, int errorContextCount) throws Buffer.BufferException {
        for (int i = 0; i < errorContextCount; i++) {
            buffer.readUInt32AsInt(); // ErrorDataLength (4 bytes)
            buffer.skip(4); // ErrorId (always SMB2_ERROR_ID_DEFAULT (0x0)) (4 bytes)
            readErrorData(header, buffer);
        }
    }

    /**
     * [MS-SMB2] 2.2.2.2 ErrorData format
     *
     * @param header
     * @param buffer
     * @return
     * @throws Buffer.BufferException
     */
    private void readErrorData(SMB2PacketHeader header, SMBBuffer buffer) throws Buffer.BufferException {
        long statusCode = header.getStatusCode();
        if (statusCode == NtStatus.STATUS_BUFFER_TOO_SMALL.getValue()) {
            this.errorData.add(new BufferTooSmallError().read(buffer));
        } else if (statusCode == NtStatus.STATUS_STOPPED_ON_SYMLINK.getValue()) {
            this.errorData.add(new SymbolicLinkError().read(buffer));
        }
    }

    public List<SMB2ErrorData> getErrorData() {
        return errorData;
    }

    public interface SMB2ErrorData {
    }

    public static class SymbolicLinkError implements SMB2ErrorData {
        private boolean absolute;
        private int unparsedPathLength;
        private String substituteName;
        private String printName;

        private SymbolicLinkError() {
        }

        private SymbolicLinkError read(SMBBuffer buffer) throws Buffer.BufferException {
            int symLinkLength = buffer.readUInt32AsInt();// SymLinkLength (4 bytes)
            int endOfResponse = buffer.rpos() + symLinkLength;
            buffer.skip(4); // SymLinkErrorTag (4 bytes) (always 0x4C4D5953)
            buffer.skip(4); // ReparseTag (4 bytes) (always 0xA000000C)
            buffer.skip(2); // ReparseDataLength (2 bytes)
            unparsedPathLength = buffer.readUInt16(); // UnparsedPathLength (2 bytes)
            int substituteNameOffset = buffer.readUInt16(); // SubstituteNameOffset (2 bytes)
            int substituteNameLength = buffer.readUInt16(); // SubstituteNameLength (2 bytes)
            int printNameOffset = buffer.readUInt16(); // PrintNameOffset (2 bytes)
            int printNameLength = buffer.readUInt16(); // PrintNameLength (2 bytes)
            absolute = buffer.readUInt32() == 0; // Flags (4 bytes)
            substituteName = readOffsettedString(buffer, substituteNameOffset, substituteNameLength); // PathBuffer (variable)
            printName = readOffsettedString(buffer, printNameOffset, printNameLength); // PathBuffer (variable)
            buffer.rpos(endOfResponse); // Set buffer to the end of the response, so that we're aligned for any next response.
            return this;
        }

        /**
         * Read a string at an offset from the current position in the buffer.
         *
         * After reading the string the position of the buffer is reset to the position where we started.
         *
         * @param offset The offset to read from
         * @param length The length of the String to read
         * @return The read String
         * @throws Buffer.BufferException If the buffer underflows.
         */
        private String readOffsettedString(SMBBuffer buffer, int offset, int length) throws Buffer.BufferException {
            int curpos = buffer.rpos();
            String s = null;
            if (length > 0) {
                buffer.rpos(curpos + offset);
                s = buffer.readString(Charsets.UTF_16, length / 2);
            }
            buffer.rpos(curpos);
            return s;
        }

        public boolean isAbsolute() {
            return absolute;
        }

        public int getUnparsedPathLength() {
            return unparsedPathLength;
        }

        public String getSubstituteName() {
            return substituteName;
        }

        public String getPrintName() {
            return printName;
        }
    }

    public static class BufferTooSmallError implements SMB2ErrorData {
        private long requiredBufferLength;

        private BufferTooSmallError() {
        }

        public BufferTooSmallError read(SMBBuffer buffer) throws Buffer.BufferException {
            this.requiredBufferLength = buffer.readUInt32(); // minimum required buffer size
            return this;
        }

        public long getRequiredBufferLength() {
            return requiredBufferLength;
        }
    }
}
