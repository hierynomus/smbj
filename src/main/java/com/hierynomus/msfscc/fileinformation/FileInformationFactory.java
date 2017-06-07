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
import com.hierynomus.smbj.common.SMBRuntimeException;

import java.nio.charset.StandardCharsets;
import java.util.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class FileInformationFactory {
    private static final Map<Class, FileInformation.Encoder> encoders;
    private static final Map<Class, FileInformation.Decoder> decoders;

    static {
        encoders = new HashMap<>();
        decoders = new HashMap<>();

        decoders.put(FileAccessInformation.class, new FileInformation.Decoder<FileAccessInformation>() {
            @Override
            public FileInformationClass getInformationClass() {
                return FileInformationClass.FileAccessInformation;
            }

            @Override
            public FileAccessInformation read(Buffer inputBuffer) throws Buffer.BufferException {
                return parseFileAccessInformation(inputBuffer);
            }
        });

        decoders.put(FileAlignmentInformation.class, new FileInformation.Decoder<FileAlignmentInformation>() {
            @Override
            public FileInformationClass getInformationClass() {
                return FileInformationClass.FileAlignmentInformation;
            }

            @Override
            public FileAlignmentInformation read(Buffer inputBuffer) throws Buffer.BufferException {
                return parseFileAlignmentInformation(inputBuffer);
            }
        });

        decoders.put(FileAllInformation.class, new FileInformation.Decoder<FileAllInformation>() {
            @Override
            public FileInformationClass getInformationClass() {
                return FileInformationClass.FileAllInformation;
            }

            @Override
            public FileAllInformation read(Buffer inputBuffer) throws Buffer.BufferException {
                return parseFileAllInformation(inputBuffer);
            }
        });

        FileInformation.Codec<FileAllocationInformation> allocationCodec = new FileInformation.Codec<FileAllocationInformation>() {
            @Override
            public FileInformationClass getInformationClass() {
                return FileInformationClass.FileAllocationInformation;
            }

            @Override
            public FileAllocationInformation read(Buffer inputBuffer) throws Buffer.BufferException {
                return parseFileAllocationInformation(inputBuffer);
            }

            @Override
            public void write(FileAllocationInformation info, Buffer outputBuffer) {
                writeFileAllocationInformation(info, outputBuffer);
            }
        };
        decoders.put(FileAllocationInformation.class, allocationCodec);
        encoders.put(FileAllocationInformation.class, allocationCodec);

        FileInformation.Codec<FileBasicInformation> basicCodec = new FileInformation.Codec<FileBasicInformation>() {
            @Override
            public FileInformationClass getInformationClass() {
                return FileInformationClass.FileBasicInformation;
            }

            @Override
            public FileBasicInformation read(Buffer inputBuffer) throws Buffer.BufferException {
                return parseFileBasicInformation(inputBuffer);
            }

            @Override
            public void write(FileBasicInformation info, Buffer outputBuffer) {
                writeFileBasicInformation(info, outputBuffer);
            }
        };
        decoders.put(FileBasicInformation.class, basicCodec);
        encoders.put(FileBasicInformation.class, basicCodec);

        decoders.put(FileEaInformation.class, new FileInformation.Decoder<FileEaInformation>() {
            @Override
            public FileInformationClass getInformationClass() {
                return FileInformationClass.FileEaInformation;
            }

            @Override
            public FileEaInformation read(Buffer inputBuffer) throws Buffer.BufferException {
                return parseFileEaInformation(inputBuffer);
            }
        });

        decoders.put(FileInternalInformation.class, new FileInformation.Decoder<FileInternalInformation>() {
            @Override
            public FileInformationClass getInformationClass() {
                return FileInformationClass.FileInternalInformation;
            }

            @Override
            public FileInternalInformation read(Buffer inputBuffer) throws Buffer.BufferException {
                return parseFileInternalInformation(inputBuffer);
            }
        });

        FileInformation.Codec<FileModeInformation> modeCodec = new FileInformation.Codec<FileModeInformation>() {
            @Override
            public FileInformationClass getInformationClass() {
                return FileInformationClass.FileModeInformation;
            }

            @Override
            public FileModeInformation read(Buffer inputBuffer) throws Buffer.BufferException {
                return parseFileModeInformation(inputBuffer);
            }

            @Override
            public void write(FileModeInformation info, Buffer outputBuffer) {
                writeFileModeInformation(info, outputBuffer);
            }
        };
        decoders.put(FileModeInformation.class, modeCodec);
        encoders.put(FileModeInformation.class, modeCodec);

        decoders.put(FilePositionInformation.class, new FileInformation.Decoder<FilePositionInformation>() {
            @Override
            public FileInformationClass getInformationClass() {
                return FileInformationClass.FilePositionInformation;
            }

            @Override
            public FilePositionInformation read(Buffer inputBuffer) throws Buffer.BufferException {
                return parseFilePositionInformation(inputBuffer);
            }
        });

        decoders.put(FileStandardInformation.class, new FileInformation.Decoder<FileStandardInformation>() {
            @Override
            public FileInformationClass getInformationClass() {
                return FileInformationClass.FileStandardInformation;
            }

            @Override
            public FileStandardInformation read(Buffer inputBuffer) throws Buffer.BufferException {
                return parseFileStandardInformation(inputBuffer);
            }
        });

        decoders.put(FileBothDirectoryInformation.class, new FileInformation.Decoder<FileBothDirectoryInformation>() {
            @Override
            public FileInformationClass getInformationClass() {
                return FileInformationClass.FileBothDirectoryInformation;
            }

            @Override
            public FileBothDirectoryInformation read(Buffer inputBuffer) throws Buffer.BufferException {
                return parseFileBothDirectoryInformation(inputBuffer);
            }
        });

        decoders.put(FileDirectoryInformation.class, new FileInformation.Decoder<FileDirectoryInformation>() {
            @Override
            public FileInformationClass getInformationClass() {
                return FileInformationClass.FileDirectoryInformation;
            }

            @Override
            public FileDirectoryInformation read(Buffer inputBuffer) throws Buffer.BufferException {
                return parseFileDirectoryInformation(inputBuffer);
            }
        });

        decoders.put(FileFullDirectoryInformation.class, new FileInformation.Decoder<FileFullDirectoryInformation>() {
            @Override
            public FileInformationClass getInformationClass() {
                return FileInformationClass.FileFullDirectoryInformation;
            }

            @Override
            public FileFullDirectoryInformation read(Buffer inputBuffer) throws Buffer.BufferException {
                return parseFileFullDirectoryInformation(inputBuffer);
            }
        });
        
        decoders.put(FileIdBothDirectoryInformation.class, new FileInformation.Decoder<FileIdBothDirectoryInformation>() {
            @Override
            public FileInformationClass getInformationClass() {
                return FileInformationClass.FileIdBothDirectoryInformation;
            }

            @Override
            public FileIdBothDirectoryInformation read(Buffer inputBuffer) throws Buffer.BufferException {
                return parseFileIdBothDirectoryInformation(inputBuffer);
            }
        });

        decoders.put(FileIdFullDirectoryInformation.class, new FileInformation.Decoder<FileIdFullDirectoryInformation>() {
            @Override
            public FileInformationClass getInformationClass() {
                return FileInformationClass.FileIdFullDirectoryInformation;
            }

            @Override
            public FileIdFullDirectoryInformation read(Buffer inputBuffer) throws Buffer.BufferException {
                return parseFileIdFullDirectoryInformation(inputBuffer);
            }
        });

        decoders.put(FileNamesInformation.class, new FileInformation.Decoder<FileNamesInformation>() {
            @Override
            public FileInformationClass getInformationClass() {
                return FileInformationClass.FileNamesInformation;
            }

            @Override
            public FileNamesInformation read(Buffer inputBuffer) throws Buffer.BufferException {
                return parseFileNamesInformation(inputBuffer);
            }
        });
    }

    @SuppressWarnings("unchecked")
    public static <F extends FileInformation> FileInformation.Encoder<F> getEncoder(F fileInformation) {
        return getEncoder((Class<F>) fileInformation.getClass());
    }

    @SuppressWarnings("unchecked")
    public static <F extends FileInformation> FileInformation.Encoder<F> getEncoder(Class<F> fileInformationClass) {
        FileInformation.Encoder encoder = encoders.get(fileInformationClass);
        if (encoder == null) {
            throw new IllegalArgumentException("FileInformationClass not supported - " + fileInformationClass);
        } else {
            return ((FileInformation.Encoder<F>) encoder);
        }
    }

    @SuppressWarnings("unchecked")
    public static <F extends FileInformation> FileInformation.Decoder<F> getDecoder(Class<F> fileInformationClass) {
        FileInformation.Decoder decoder = decoders.get(fileInformationClass);
        if (decoder == null) {
            throw new IllegalArgumentException("FileInformationClass not supported - " + fileInformationClass);
        } else {
            return ((FileInformation.Decoder<F>) decoder);
        }
    }

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
            default:
                new UnsupportedOperationException(timeClass.toString());
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
     * @param decoder
     * @return
     * @throws Buffer.BufferException
     */
    public static <F extends FileDirectoryQueryableInformation> List<F> parseFileInformationList(
        byte[] data, FileInformation.Decoder<F> decoder)
        throws Buffer.BufferException {

        List<F> _fileInfoList = new ArrayList<>();
        Iterator<F> iterator = createFileInformationIterator(data, decoder);
        while (iterator.hasNext()) {
            _fileInfoList.add(iterator.next());
        }
        return _fileInfoList;
    }

    public static <F extends FileDirectoryQueryableInformation> Iterator<F> createFileInformationIterator(byte[] data, FileInformation.Decoder<F> decoder) {
        return new FileInfoIterator<>(data, decoder, 0);
    }

    private static class FileInfoIterator<F extends FileDirectoryQueryableInformation> implements Iterator<F> {
        private final Buffer.PlainBuffer buffer;
        private final FileInformation.Decoder<F> decoder;
        private int offsetStart;
        private F next;

        FileInfoIterator(byte[] data, FileInformation.Decoder<F> decoder, int offsetStart) {
            this.buffer = new Buffer.PlainBuffer(data, Endian.LE);
            this.decoder = decoder;
            this.offsetStart = offsetStart;
            this.next = prepareNext();
        }

        @Override
        public boolean hasNext() {
            return next != null;
        }

        @Override
        public F next() {
            if (next == null) {
                throw new NoSuchElementException();
            }

            F fileInfo = this.next;
            this.next = prepareNext();
            return fileInfo;
        }

        private F prepareNext() {
            try {
                F next = null;

                while (next == null && offsetStart != -1) {
                    buffer.rpos(offsetStart);
                    F fileInfo = decoder.read(buffer);
                    int nextOffset = (int) fileInfo.getNextOffset();

                    if (nextOffset == 0) {
                        offsetStart = -1;
                    } else {
                        offsetStart += nextOffset;
                    }

                    if (!(".".equals(fileInfo.getFileName()) || "..".equals(fileInfo.getFileName()))) {
                        next = fileInfo;
                    }
                }

                return next;
            } catch (Buffer.BufferException e) {
                throw new SMBRuntimeException(e);
            }
        }

        @Override
        public void remove() {
            throw new UnsupportedOperationException();
        }
    }

    /**
     * [MS-SMB2] 2.2.38 SMB2 QUERY_INFO Response, SMB2_0_INFO_FILE/FileAllInformation
     * <p>
     * [MS-FSCC] 2.4.2 FileAllInformation
     */
    public static FileAllInformation parseFileAllInformation(Buffer<?> buffer) throws Buffer.BufferException {
        FileBasicInformation basicInformation = parseFileBasicInformation(buffer);
        FileStandardInformation standardInformation = parseFileStandardInformation(buffer);
        FileInternalInformation internalInformation = parseFileInternalInformation(buffer);
        FileEaInformation eaInformation = parseFileEaInformation(buffer);
        FileAccessInformation accessInformation = parseFileAccessInformation(buffer);
        FilePositionInformation positionInformation = parseFilePositionInformation(buffer);
        FileModeInformation modeInformation = parseFileModeInformation(buffer);
        FileAlignmentInformation alignmentInformation = parseFileAlignmentInformation(buffer);
        String nameInformation = parseFileNameInformation(buffer);

        FileAllInformation fi = new FileAllInformation(
            basicInformation,
            standardInformation,
            internalInformation,
            eaInformation,
            accessInformation,
            positionInformation,
            modeInformation,
            alignmentInformation,
            nameInformation
        );
        return fi;
    }

    private static String parseFileNameInformation(Buffer<?> buffer) throws Buffer.BufferException {
        long fileNameLen = buffer.readUInt32(); // File name length
        String fileName = buffer.readString(StandardCharsets.UTF_16LE, (int) fileNameLen / 2);
        return fileName;
    }

    private static FileBasicInformation parseFileBasicInformation(Buffer<?> buffer) throws Buffer.BufferException {
        FileTime creationTime = MsDataTypes.readFileTime(buffer);
        FileTime lastAccessTime = MsDataTypes.readFileTime(buffer);
        FileTime lastWriteTime = MsDataTypes.readFileTime(buffer);
        FileTime changeTime = MsDataTypes.readFileTime(buffer);
        long fileAttributes = buffer.readUInt32(); // File Attributes
        buffer.skip(4); // Reserved (4 bytes)

        return new FileBasicInformation(creationTime, lastAccessTime, lastWriteTime, changeTime, fileAttributes);
    }

    private static void writeFileBasicInformation(FileBasicInformation information, Buffer<?> buffer) {
        MsDataTypes.putFileTime(information.getCreationTime(), buffer);
        MsDataTypes.putFileTime(information.getLastAccessTime(), buffer);
        MsDataTypes.putFileTime(information.getLastWriteTime(), buffer);
        MsDataTypes.putFileTime(information.getChangeTime(), buffer);
        buffer.putUInt32(information.getFileAttributes());
        buffer.putUInt32(0); // Reserved (4 bytes)
    }

    private static FileStandardInformation parseFileStandardInformation(Buffer<?> buffer) throws Buffer.BufferException {
        long allocationSize = buffer.readLong();
        long endOfFile = buffer.readUInt64();
        long numberOfLinks = buffer.readUInt32();
        boolean deletePending = buffer.readBoolean();
        boolean directory = buffer.readBoolean();
        buffer.skip(2); // Reserved
        return new FileStandardInformation(allocationSize, endOfFile, numberOfLinks, deletePending, directory);
    }

    private static FileInternalInformation parseFileInternalInformation(Buffer<?> buffer) throws Buffer.BufferException {
        long indexNumber = buffer.readLong();
        return new FileInternalInformation(indexNumber);
    }

    private static FileEaInformation parseFileEaInformation(Buffer<?> buffer) throws Buffer.BufferException {
        long eaSize = buffer.readUInt32();
        return new FileEaInformation(eaSize);
    }

    private static FileAccessInformation parseFileAccessInformation(Buffer<?> buffer) throws Buffer.BufferException {
        int accessFlags = (int) buffer.readUInt32();
        return new FileAccessInformation(accessFlags);
    }

    private static FileAllocationInformation parseFileAllocationInformation(Buffer<?> buffer) throws Buffer.BufferException {
        long allocationSize = buffer.readLong();
        return new FileAllocationInformation(allocationSize);
    }

    private static void writeFileAllocationInformation(FileAllocationInformation info, Buffer outputBuffer) {
        outputBuffer.putLong(info.getAllocationSize());
    }

    private static FilePositionInformation parseFilePositionInformation(Buffer<?> buffer) throws Buffer.BufferException {
        long currentByteOffset = buffer.readLong();
        return new FilePositionInformation(currentByteOffset);
    }

    private static FileModeInformation parseFileModeInformation(Buffer<?> buffer) throws Buffer.BufferException {
        int mode = (int) buffer.readUInt32();
        return new FileModeInformation(mode);
    }

    private static void writeFileModeInformation(FileModeInformation info, Buffer outputBuffer) {
        outputBuffer.putUInt32(info.getMode() & 0xFFFFFFFFL);
    }

    private static FileAlignmentInformation parseFileAlignmentInformation(Buffer<?> buffer) throws Buffer.BufferException {
        long alignmentReq = buffer.readUInt32();
        return new FileAlignmentInformation(alignmentReq);
    }

    /**
     * 2.4.8 FileBothDirectoryInformation
     */
    public static FileBothDirectoryInformation parseFileBothDirectoryInformation(Buffer<?> buffer) throws Buffer.BufferException {
        long nextOffset = buffer.readUInt32();
        long fileIndex = buffer.readUInt32();
        FileTime creationTime = MsDataTypes.readFileTime(buffer);
        FileTime lastAccessTime = MsDataTypes.readFileTime(buffer);
        FileTime lastWriteTime = MsDataTypes.readFileTime(buffer);
        FileTime changeTime = MsDataTypes.readFileTime(buffer);
        long endOfFile = buffer.readUInt64();
        long allocationSize = buffer.readUInt64();
        long fileAttributes = buffer.readUInt32();
        long fileNameLen = buffer.readUInt32();
        long eaSize = buffer.readUInt32();
        byte shortNameLen = buffer.readByte();
        buffer.readByte(); // Reserved1 (1)
        byte[] shortNameBytes = buffer.readRawBytes(24);// Shortname
        String shortName = new String(shortNameBytes, 0, shortNameLen, StandardCharsets.UTF_16LE);
        buffer.readUInt16(); // Reserved2
        String fileName = buffer.readString(StandardCharsets.UTF_16LE, (int) fileNameLen / 2);
        FileBothDirectoryInformation fi = new FileBothDirectoryInformation(
            nextOffset, fileIndex, fileName,
            creationTime, lastAccessTime, lastWriteTime, changeTime,
            endOfFile, allocationSize,
            fileAttributes,
            eaSize,
            shortName
        );
        return fi;
    }

    /**
     * 2.4.10 FileDirectoryInformation
     */
    public static FileDirectoryInformation parseFileDirectoryInformation(Buffer<?> buffer) throws Buffer.BufferException {
        long nextOffset = buffer.readUInt32();
        long fileIndex = buffer.readUInt32();
        FileTime creationTime = MsDataTypes.readFileTime(buffer);
        FileTime lastAccessTime = MsDataTypes.readFileTime(buffer);
        FileTime lastWriteTime = MsDataTypes.readFileTime(buffer);
        FileTime changeTime = MsDataTypes.readFileTime(buffer);
        long endOfFile = buffer.readUInt64();
        long allocationSize = buffer.readUInt64();
        long fileAttributes = buffer.readUInt32();
        long fileNameLen = buffer.readUInt32();
        String fileName = buffer.readString(StandardCharsets.UTF_16LE, (int) fileNameLen / 2);
        FileDirectoryInformation fi = new FileDirectoryInformation(
            nextOffset, fileIndex, fileName,
            creationTime, lastAccessTime, lastWriteTime, changeTime,
            endOfFile, allocationSize,
            fileAttributes
        );
        return fi;
    }

    /**
     * 2.4.14 FileFullDirectoryInformation
     */
    public static FileFullDirectoryInformation parseFileFullDirectoryInformation(Buffer<?> buffer) throws Buffer.BufferException {
        long nextOffset = buffer.readUInt32();
        long fileIndex = buffer.readUInt32();
        FileTime creationTime = MsDataTypes.readFileTime(buffer);
        FileTime lastAccessTime = MsDataTypes.readFileTime(buffer);
        FileTime lastWriteTime = MsDataTypes.readFileTime(buffer);
        FileTime changeTime = MsDataTypes.readFileTime(buffer);
        long endOfFile = buffer.readUInt64();
        long allocationSize = buffer.readUInt64();
        long fileAttributes = buffer.readUInt32();
        long fileNameLen = buffer.readUInt32();
        long eaSize = buffer.readUInt32();
        String fileName = buffer.readString(StandardCharsets.UTF_16LE, (int) fileNameLen / 2);
        FileFullDirectoryInformation fi = new FileFullDirectoryInformation(
            nextOffset, fileIndex, fileName,
            creationTime, lastAccessTime, lastWriteTime, changeTime,
            endOfFile, allocationSize,
            fileAttributes,
            eaSize
        );
        return fi;
    }

    /**
     * 2.4.17 FileIdBothDirectoryInformation
     */
    public static FileIdBothDirectoryInformation parseFileIdBothDirectoryInformation(Buffer<?> buffer) throws Buffer.BufferException {
        long nextOffset = buffer.readUInt32();
        long fileIndex = buffer.readUInt32();
        FileTime creationTime = MsDataTypes.readFileTime(buffer);
        FileTime lastAccessTime = MsDataTypes.readFileTime(buffer);
        FileTime lastWriteTime = MsDataTypes.readFileTime(buffer);
        FileTime changeTime = MsDataTypes.readFileTime(buffer);
        long endOfFile = buffer.readUInt64();
        long allocationSize = buffer.readUInt64();
        long fileAttributes = buffer.readUInt32();
        long fileNameLen = buffer.readUInt32();
        long eaSize = buffer.readUInt32();
        byte shortNameLen = buffer.readByte();
        buffer.readByte(); // Reserved1 (1)
        byte[] shortNameBytes = buffer.readRawBytes(24);// Shortname
        String shortName = new String(shortNameBytes, 0, shortNameLen, StandardCharsets.UTF_16LE);
        buffer.readUInt16(); // Reserved2
        byte[] fileId = buffer.readRawBytes(8);
        String fileName = buffer.readString(StandardCharsets.UTF_16LE, (int) fileNameLen / 2);
        FileIdBothDirectoryInformation fi = new FileIdBothDirectoryInformation(
            nextOffset, fileIndex, fileName,
            creationTime, lastAccessTime, lastWriteTime, changeTime,
            endOfFile, allocationSize,
            fileAttributes,
            eaSize,
            shortName,
            fileId
        );
        return fi;
    }

    /**
     * 2.4.18 FileIdFullDirectoryInformation
     */
    public static FileIdFullDirectoryInformation parseFileIdFullDirectoryInformation(Buffer<?> buffer) throws Buffer.BufferException {
        long nextOffset = buffer.readUInt32();
        long fileIndex = buffer.readUInt32();
        FileTime creationTime = MsDataTypes.readFileTime(buffer);
        FileTime lastAccessTime = MsDataTypes.readFileTime(buffer);
        FileTime lastWriteTime = MsDataTypes.readFileTime(buffer);
        FileTime changeTime = MsDataTypes.readFileTime(buffer);
        long endOfFile = buffer.readUInt64();
        long allocationSize = buffer.readUInt64();
        long fileAttributes = buffer.readUInt32();
        long fileNameLen = buffer.readUInt32();
        long eaSize = buffer.readUInt32();
        buffer.skip(4); // Reserved
        byte[] fileId = buffer.readRawBytes(8);
        String fileName = buffer.readString(StandardCharsets.UTF_16LE, (int) fileNameLen / 2);
        FileIdFullDirectoryInformation fi = new FileIdFullDirectoryInformation(
            nextOffset, fileIndex, fileName,
            creationTime, lastAccessTime, lastWriteTime, changeTime,
            endOfFile, allocationSize,
            fileAttributes,
            eaSize,
            fileId
        );
        return fi;
    }

    /**
     * 2.4.26 FileNamesInformation
     */
    public static FileNamesInformation parseFileNamesInformation(Buffer<?> buffer) throws Buffer.BufferException {
        long nextOffset = buffer.readUInt32();
        long fileIndex = buffer.readUInt32();
        long fileNameLen = buffer.readUInt32();
        String fileName = buffer.readString(StandardCharsets.UTF_16LE, (int) fileNameLen / 2);
        FileNamesInformation fi = new FileNamesInformation(
            nextOffset, fileIndex, fileName
        );
        return fi;
    }
}
