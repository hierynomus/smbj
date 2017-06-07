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

import com.hierynomus.msdtyp.FileTime;
import com.hierynomus.msdtyp.MsDataTypes;
import com.hierynomus.msfscc.FileInformationClass;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
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
        return deleteOnClose ? new byte[]{1} : new byte[]{0};
    }

    /**
     * MS-FSCC 2.4.7 FileBasicInformation for SMB2
     */
    public static byte[] getFileBasicInfo(
        FileTime creationTime,
        FileTime lastAccessTime,
        FileTime lastWriteTime,
        FileTime changeTime,
        long fileAttributes)
        throws Buffer.BufferException {

        Buffer.PlainBuffer buffer = new Buffer.PlainBuffer(Endian.LE);
        MsDataTypes.putFileTime(creationTime, buffer); // CreationTime
        MsDataTypes.putFileTime(lastAccessTime, buffer); // LastAccessTime
        MsDataTypes.putFileTime(lastWriteTime, buffer); // LastWriteTime
        MsDataTypes.putFileTime(changeTime, buffer); // ChangeTime
        buffer.putUInt32(fileAttributes); // FileAttributes
        buffer.putUInt32(0); // Reserved (4 bytes)
        return buffer.getCompactData();
    }

    /**
     * * MS-FSCC 2.4.7 FileBasicInformation for SMB2
     */
    public static byte[] getFileBasicInfo(
        FileTime timeToSet,
        FileBasicInformationEnum timeClass)
        throws Buffer.BufferException {

        Buffer.PlainBuffer buffer = new Buffer.PlainBuffer(Endian.LE);

        switch (timeClass) {
            case CreationTime:
                MsDataTypes.putFileTime(timeToSet, buffer); // CreationTime
                buffer.putUInt64(0, Endian.LE); // LastAccessTime, 0 means must not change the LastAccessTime
                buffer.putUInt64(0, Endian.LE); // LastWriteTime, 0 means must not change the LastWriteTime
                buffer.putUInt64(0, Endian.LE); // ChangeTime, 0 means must not change the ChangeTime
                break;
            case LastAccessTime:
                buffer.putUInt64(0, Endian.LE); // CreationTime, 0 means must not change the CreationTime
                MsDataTypes.putFileTime(timeToSet, buffer); // LastAccessTime
                buffer.putUInt64(0, Endian.LE); // LastWriteTime, 0 means must not change the LastWriteTime
                buffer.putUInt64(0, Endian.LE); // ChangeTime, 0 means must not change the ChangeTime
                break;
            case LastWriteTime:
                buffer.putUInt64(0, Endian.LE); // CreationTime, 0 means must not change the CreationTime
                buffer.putUInt64(0, Endian.LE); // LastAccessTime, 0 means must not change the LastAccessTime
                MsDataTypes.putFileTime(timeToSet, buffer); // LastWriteTime
                buffer.putUInt64(0, Endian.LE); // ChangeTime, 0 means must not change the ChangeTime
                break;
            case ChangeTime:
                buffer.putUInt64(0, Endian.LE); // CreationTime, 0 means must not change the CreationTime
                buffer.putUInt64(0, Endian.LE); // LastAccessTime, 0 means must not change the LastAccessTime
                buffer.putUInt64(0, Endian.LE); // LastWriteTime, 0 means must not change the LastWriteTime
                MsDataTypes.putFileTime(timeToSet, buffer); // ChangeTime
                break;
        }

        buffer.putUInt32(0); // FileAttributes, 0 means must not change the file attribute
        buffer.putUInt32(0); // Reserved (4 bytes)

        return buffer.getCompactData();
    }

    /**
     * * MS-FSCC 2.4.7 FileBasicInformation for SMB2
     */
    public static byte[] getFileBasicInfo(
        long fileAttributes)
        throws Buffer.BufferException {

        Buffer.PlainBuffer buffer = new Buffer.PlainBuffer(Endian.LE);
        buffer.putUInt64(0, Endian.LE); // CreationTime, 0 means must not change the CreationTime
        buffer.putUInt64(0, Endian.LE); // LastAccessTime, 0 means must not change the LastAccessTime
        buffer.putUInt64(0, Endian.LE); // LastWriteTime, 0 means must not change the LastWriteTime
        buffer.putUInt64(0, Endian.LE); // ChangeTime, 0 means must not change the ChangeTime
        buffer.putUInt32(fileAttributes); // FileAttributes
        buffer.putUInt32(0); // Reserved (4 bytes)
        return buffer.getCompactData();
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
        do {
            nextEntryOffset = (int) buffer.readUInt32();
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
     * <p>
     * [MS-FSCC] 2.4.2 FileAllInformation
     */
    public static FileInfo parseFileAllInformation(Buffer.PlainBuffer buffer) throws Buffer.BufferException {
        // Basic Information
        FileTime creationTime = MsDataTypes.readFileTime(buffer);
        FileTime lastAccessTime = MsDataTypes.readFileTime(buffer);
        FileTime lastWriteTime = MsDataTypes.readFileTime(buffer);
        FileTime changeTime = MsDataTypes.readFileTime(buffer);
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
        FileInfo fi = new FileInfo(fileName, fileId, creationTime, lastAccessTime, lastWriteTime, changeTime, fileAttributes, fileSize, accessMask);
        return fi;
    }

    /**
     * 2.4.17 FileIdBothDirectoryInformation
     */
    public static FileInfo parseFileIdBothDirectoryInformation(Buffer.PlainBuffer buffer) throws Buffer.BufferException {
        FileTime creationTime = MsDataTypes.readFileTime(buffer);
        FileTime lastAccessTime = MsDataTypes.readFileTime(buffer);
        FileTime lastWriteTime = MsDataTypes.readFileTime(buffer);
        FileTime changeTime = MsDataTypes.readFileTime(buffer);
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
        FileInfo fi = new FileInfo(fileName, fileId, creationTime, lastAccessTime, lastWriteTime, changeTime, fileAttributes, fileSize, 0);
        return fi;
    }
}
