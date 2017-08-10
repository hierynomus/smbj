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

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.FileNotifyAction;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * [MS-SMB2].pdf 2.2.36 SMB2 CHANGE_NOTIFY Response
 * <p>
 * \
 */
public class SMB2ChangeNotifyResponse extends SMB2Packet {

    List<FileNotifyInfo> fileNotifyInfoList = new ArrayList<>();

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        buffer.skip(2); // StructureSize (2 bytes)
        int outputBufferOffset = buffer.readUInt16(); // OutputBufferOffset (2 bytes)
        int length = buffer.readUInt32AsInt();// OutputBufferLength (4 bytes)
        if (outputBufferOffset > 0 && length > 0) {
            fileNotifyInfoList = readFileNotifyInfo(buffer, outputBufferOffset);
        }
    }

    /**
     * [MS-SMB2].pdf 3.3.4.4
     * STATUS_NOTIFY_ENUM_DIR should be treated as a success code.
     * @param status The status to verify
     * @return
     */
    @Override
    protected boolean isSuccess(NtStatus status) {
        return super.isSuccess(status) || status == NtStatus.STATUS_NOTIFY_ENUM_DIR;
    }

    private List<FileNotifyInfo> readFileNotifyInfo(SMBBuffer buffer, int outputBufferOffset)
        throws Buffer.BufferException {
        List<FileNotifyInfo> notifyInfoList = new ArrayList<>();
        buffer.rpos(outputBufferOffset);
        int currentPos = buffer.rpos();
        int nextEntryOffset;
        long fileNameLen;
        String fileName;

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
