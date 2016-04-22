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

import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.protocol.commons.EnumWithValue;

import java.text.DecimalFormat;
import java.util.List;

public class FileInfo {

    byte[] fileId; // This is not the SMB2FileId, but not sure what one can do with this id.
    String fileName;
    long fileAttributes;
    long fileSize;
    long accessMask;


    public FileInfo(String fileName, byte[] fileId, long fileAttributes, long fileSize, long accessMask) {
        this.fileName = fileName;
        this.fileId = fileId;
        this.fileAttributes = fileAttributes;
        this.fileSize = fileSize;
        this.accessMask = accessMask;
    }

    public byte[] getFileId() {
        return fileId;
    }

    public String getFileName() {
        return fileName;
    }

    public long getFileAttributes() {
        return fileAttributes;
    }

    public long getFileSize() {
        return fileSize;
    }

    public long getAccessMask() {
        return accessMask;
    }

    @Override
    public String toString() {
        return "FileInfo{" +
                "fileName='" + fileName + '\'' +
                "fileSize='" + fileSize + '\'' +
                ", fileAttributes=" + EnumWithValue.EnumUtils.toEnumSet(fileAttributes, FileAttributes.class) +
                '}';
    }

    public static void printList(List<FileInfo> fileInfos) {
        String format = "%-50s %-10s %-50s\n";
        System.out.printf(format, "Name", "Size", "Attributes");
        System.out.printf(format, "----", "----", "----------");
        for (FileInfo fi: fileInfos) {
            System.out.printf(format, fi.getFileName(), readableFileSize(fi.getFileSize()),
                    EnumWithValue.EnumUtils.toEnumSet(fi.getFileAttributes(), FileAttributes.class));
        }
    }

    static String readableFileSize(long size) {
        if(size <= 0) return "0";
        final String[] units = new String[] { "B", "KB", "MB", "GB", "TB", "PB", "EB" };
        int digitGroups = (int) (Math.log10(size)/Math.log10(1024));
        String result = null;
        result = new DecimalFormat("#,##0.#").format(size/Math.pow(1024, digitGroups)) + " " + units[digitGroups];
        return result;
    }

}
