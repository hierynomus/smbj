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
package com.hierynomus.msfscc.directory;

import com.hierynomus.msfscc.FileNotifyAction;
import com.hierynomus.protocol.commons.Charsets;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;

public class FileNotifyInformation {

    private int nextEntryOffset;
    private FileNotifyAction action;
    private String fileName;

    public FileNotifyInformation() {
    }

    public void read(Buffer buffer) throws Buffer.BufferException {
        this.nextEntryOffset = buffer.readUInt32AsInt(); // NextEntryOffset (4 bytes)
        this.action = EnumWithValue.EnumUtils.valueOf(buffer.readUInt32(), FileNotifyAction.class, null); // Action (4 bytes)
        long fileNameLength = buffer.readUInt32(); // FileNameLength (4 bytes)
        this.fileName = buffer.readString(Charsets.UTF_16LE, (int) fileNameLength / 2); // FileName (variable)
    }

    public int getNextEntryOffset() {
        return nextEntryOffset;
    }

    public FileNotifyAction getAction() {
        return action;
    }

    public String getFileName() {
        return fileName;
    }

    @Override
    public String toString() {
        return "FileNotifyInformation{" +
            "action=" + action +
            ", fileName='" + fileName + '\'' +
            '}';
    }
}
