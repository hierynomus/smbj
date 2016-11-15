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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.FileNotifyAction;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.BufferException;
import com.hierynomus.smbj.common.SMBBuffer;

/**
 * [MS-SMB2].pdf 2.2.36 SMB2 CHANGE_NOTIFY Response
 * <p>
 * \
 */
public class SMB2ChangeNotifyResponse extends SMB2Packet {

    List<FileNotifyInfo> fileNotifyInfoList = new ArrayList<>();

    public SMB2ChangeNotifyResponse() {
        super();
    }

    @Override
    protected void readMessage(SMBBuffer buffer) throws BufferException {
        buffer.skip(2); // StructureSize (2 bytes)
        int outputBufferOffset = buffer.readUInt16(); // OutputBufferOffset (2 bytes)
        int outBufferLength = buffer.readUInt32AsInt(); // OutputBufferLength (4 bytes)
        if (getHeader().getStatus() == NtStatus.STATUS_SUCCESS) {
            fileNotifyInfoList = readFileNotifyInfo(buffer, outputBufferOffset, outBufferLength);
        }
    }

    private List<FileNotifyInfo> readFileNotifyInfo(SMBBuffer buffer, int outputBufferOffset, int outBufferLength)
        throws BufferException {
        List<FileNotifyInfo> notifyInfoList = new ArrayList<>();
        buffer.rpos(outputBufferOffset);
        int currentPos = buffer.rpos();
        int nextEntryOffset = 0;
        long fileNameLen = 0;
        String fileName = null;

        do {
            nextEntryOffset = (int) buffer.readUInt32();
            FileNotifyAction action = EnumWithValue.EnumUtils.valueOf(buffer.readUInt32(), FileNotifyAction.class, null);
            fileNameLen = buffer.readUInt32();
            fileName = buffer.readString(StandardCharsets.UTF_16LE, (int) fileNameLen / 2);
            notifyInfoList.add(new FileNotifyInfo(action, fileName));
            currentPos += nextEntryOffset;
            buffer.rpos(currentPos);
        } while (nextEntryOffset != 0);

        return notifyInfoList;
    }

    public List<FileNotifyInfo> getFileNotifyInfoList() {
        return fileNotifyInfoList;
    }

    public class FileNotifyInfo {
        FileNotifyAction action;
        String fileName;

        FileNotifyInfo(FileNotifyAction action, String fileName) {
            this.action = action;
            this.fileName = fileName;
        }

        public FileNotifyAction getAction() {
            return action;
        }

        public String getFileName() {
            return fileName;
        }

        @Override
        public String toString() {
            return "FileNotifyInfo{" +
                "action=" + action +
                ", fileName='" + fileName + '\'' +
                '}';
        }
    }
}
