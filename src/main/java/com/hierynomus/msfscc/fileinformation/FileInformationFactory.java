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
package com.hierynomus.msfscc.fileinformation;

import com.hierynomus.msdtyp.MsDataTypes;
import com.hierynomus.msfscc.FileInformationClass;
import com.hierynomus.ntlm.functions.NtlmFunctions;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class FileInformationFactory {

    /**
     * MS-FSCC 2.4.34.2 FileRenameInformation for SMB2
     */
    public static byte[] getRenameInfo(boolean replaceIfExists, String newName) {
        Buffer.PlainBuffer renBuf = new Buffer.PlainBuffer(Endian.LE);
        renBuf.putByte((byte) (replaceIfExists ? 1 : 0));
        renBuf.putRawBytes(new byte[]{0, 0, 0, 0, 0, 0, 0});
        renBuf.putUInt64(0);
        renBuf.putUInt32(newName.length() * 2); // unicode
        renBuf.putRawBytes(newName.getBytes(StandardCharsets.UTF_16));
        return renBuf.getCompactData();
    }

    /**
     * MS-FSCC 2.4.11 FileDispositionInformation for SMB2
     */
    public static byte[] getFileDispositionInfo(boolean deleteOnClose) {
        Buffer.PlainBuffer fileDispBuf = new Buffer.PlainBuffer(Endian.LE);
        fileDispBuf.putByte((byte) (deleteOnClose ? 1 : 0));
        return fileDispBuf.getCompactData();
    }

    /**
     * [MS-SMB2] 2.2.34 SMB2 QUERY_DIRECTORY Response for FileInformationClass->FileIdBothDirectoryInformation
     *
     * @param data
     * @param fileInformationClass
     * @return
     * @throws Buffer.BufferException
     */
    public static List<FileInfo> parseFileInformationList(
            byte[] data, FileInformationClass fileInformationClass)
            throws Buffer.BufferException {

        Buffer.PlainBuffer buffer = new Buffer.PlainBuffer(data, Endian.LE);
        List<FileInfo> _fileInfoList = new ArrayList<>();
        int offsetStart = 0;
        int nextEntryOffset = offsetStart;
        long fileIndex = 0;
        do  {
            nextEntryOffset = (int)buffer.readUInt32();
            fileIndex = buffer.readUInt32();
            FileInfo fileInfo = null;
            switch (fileInformationClass) {
                case FileIdBothDirectoryInformation:
                    fileInfo = parseFileIdBothDirectoryInformation(buffer);
                    break;
                case FileAllInformation:
                    fileInfo = parseFileAllInformation(buffer);
                    break;
                default:
                    throw new IllegalArgumentException("FileInformationClass not supported - " + fileInformationClass);
            }
            if (!(".".equals(fileInfo.getFileName()) || "..".equals(fileInfo.getFileName()))) {
                _fileInfoList.add(fileInfo);
            }
            offsetStart += nextEntryOffset;
            buffer.rpos(offsetStart);
        } while (nextEntryOffset != 0);
        return _fileInfoList;
    }


    /**
     * [MS-SMB2] 2.2.38 SMB2 QUERY_INFO Response, SMB2_0_INFO_FILE/FileAllInformation
     *
     * [MS-FSCC] 2.4.2 FileAllInformation
     */
    public static FileInfo parseFileAllInformation(Buffer.PlainBuffer buffer) throws Buffer.BufferException {
        // Basic Information
        Date creationTime = MsDataTypes.readFileTime(buffer);
        Date lastAccessTime = MsDataTypes.readFileTime(buffer);
        Date lastWriteTime = MsDataTypes.readFileTime(buffer);
        Date changeTime = MsDataTypes.readFileTime(buffer);
        long fileAttributes = buffer.readUInt32(); // File Attributes
        buffer.skip(4); // Reserved (4 bytes)

        // StandardInformation
        buffer.skip(8); // AllocationSize - Ignored
        long fileSize = buffer.readUInt64(); // EndOfFile - Ignored
        buffer.skip(4); // NumberOfLinks
        buffer.skip(1); // Delete Pending
        buffer.skip(1); // Directory
        buffer.skip(2); // Reserved

        // FileInternalInformation
        byte[] fileId = buffer.readRawBytes(8);

        // FileEaInformation
        buffer.skip(4); // EaSize

        // FileAccessInformation
        long accessMask = buffer.readUInt32(); // Access Flags (4 bytes)

        // FilePositionInformation
        buffer.skip(8);

        // FileModeInformation
        buffer.skip(4);

        // AlignmentInformation
        buffer.skip(4);

        // FileNameInformation
        long fileNameLen = buffer.readUInt32(); // File name length
        String fileName = buffer.readString(StandardCharsets.UTF_16LE, (int) fileNameLen / 2);
        FileInfo fi = new FileInfo(fileName, fileId, fileAttributes, fileSize, accessMask);
        return fi;
    }

    /**
     * 2.4.17 FileIdBothDirectoryInformation
     */
    public static FileInfo parseFileIdBothDirectoryInformation(Buffer.PlainBuffer buffer) throws Buffer.BufferException {
        Date creationTime = MsDataTypes.readFileTime(buffer);
        Date lastAccessTime = MsDataTypes.readFileTime(buffer);
        Date lastWriteTime = MsDataTypes.readFileTime(buffer);
        Date changeTime = MsDataTypes.readFileTime(buffer);
        long fileSize = buffer.readUInt64(); // EndOfFile - Ignored
        buffer.readRawBytes(8); // AllocationSize - Ignored
        long fileAttributes = buffer.readUInt32(); // File Attributes
        long fileNameLen = buffer.readUInt32(); // File name length
        buffer.readUInt32(); // EaSize - Ignored
        buffer.readByte(); // Shortname length (1)
        buffer.readByte(); // Reserved1 (1)
        buffer.readRawBytes(24); // Shortname
        buffer.readUInt16(); // Reserved2
        byte[] fileId = buffer.readRawBytes(8);
        String fileName = buffer.readString(StandardCharsets.UTF_16LE, (int) fileNameLen / 2);
        FileInfo fi = new FileInfo(fileName, fileId, fileAttributes, fileSize, 0);
        return fi;
    }
}
