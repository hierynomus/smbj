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

import java.util.ArrayList;
import java.util.List;

import com.hierynomus.msfscc.directory.FileNotifyInformation;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

/**
 * [MS-SMB2].pdf 2.2.36 SMB2 CHANGE_NOTIFY Response
 *
 */
public class SMB2ChangeNotifyResponse extends SMB2Packet {

    List<FileNotifyInformation> fileNotifyInfoList = new ArrayList<>();

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        buffer.skip(2); // StructureSize (2 bytes)
        int outputBufferOffset = buffer.readUInt16(); // OutputBufferOffset (2 bytes)
        int length = buffer.readUInt32AsInt();// OutputBufferLength (4 bytes)
        if (outputBufferOffset > 0 && length > 0) {
            fileNotifyInfoList = readFileNotifyInfo(buffer, outputBufferOffset);
        }
        // Ensure the read position is set to the end of this packet.
        // The FileNotifyInfo blocks have padding to align them on 4 byte boundaries.
        buffer.rpos(header.getHeaderStartPosition() + outputBufferOffset + length);
    }

    private List<FileNotifyInformation> readFileNotifyInfo(SMBBuffer buffer, int outputBufferOffset)
        throws Buffer.BufferException {
        List<FileNotifyInformation> notifyInfoList = new ArrayList<>();
        buffer.rpos(header.getHeaderStartPosition() + outputBufferOffset); // Ensure that we move relative to the header position

        for (;;) {
            int entryStartPos = buffer.rpos();
            FileNotifyInformation info = new FileNotifyInformation();
            info.read(buffer);
            notifyInfoList.add(info);
            if (info.getNextEntryOffset() == 0) {
                break;
            }

            entryStartPos += info.getNextEntryOffset();
            buffer.rpos(entryStartPos);
        }

        return notifyInfoList;
    }

    public List<FileNotifyInformation> getFileNotifyInfoList() {
        return fileNotifyInfoList;
    }

}
