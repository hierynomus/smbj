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
package com.hierynomus.smbj.share;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.SecurityDescriptor;
import com.hierynomus.msdtyp.SecurityInformation;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.FileSystemInformationClass;
import com.hierynomus.msfscc.fileinformation.*;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2CreateResponse;
import com.hierynomus.mssmb2.messages.SMB2QueryInfoRequest;
import com.hierynomus.mssmb2.messages.SMB2SetInfoRequest;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.common.SmbPath;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static com.hierynomus.msdtyp.AccessMask.*;
import static com.hierynomus.msfscc.FileAttributes.FILE_ATTRIBUTE_DIRECTORY;
import static com.hierynomus.msfscc.FileAttributes.FILE_ATTRIBUTE_NORMAL;
import static com.hierynomus.mssmb2.SMB2CreateDisposition.FILE_CREATE;
import static com.hierynomus.mssmb2.SMB2CreateDisposition.FILE_OPEN;
import static com.hierynomus.mssmb2.SMB2ShareAccess.*;
import static com.hierynomus.mssmb2.messages.SMB2QueryInfoRequest.SMB2QueryInfoType.SMB2_0_INFO_SECURITY;

public class DiskShare extends Share {
    public DiskShare(SmbPath smbPath, TreeConnect treeConnect) {
        super(smbPath, treeConnect);
    }

    public DiskEntry open(String path, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        SMB2CreateResponse response = createFile(path, null, accessMask, attributes, shareAccesses, createDisposition, createOptions);
        return getDiskEntry(path, response);
    }

    protected DiskEntry getDiskEntry(String path, SMB2CreateResponse response) {
        if (response.getFileAttributes().contains(FILE_ATTRIBUTE_DIRECTORY)) {
            return new Directory(response.getFileId(), this, path);
        } else {
            return new File(response.getFileId(), this, path);
        }
    }

    /**
     * Get a handle to a directory in the given path
     */
    public Directory openDirectory(String path, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        EnumSet<SMB2CreateOptions> actualCreateOptions = createOptions != null ? EnumSet.copyOf(createOptions) : EnumSet.noneOf(SMB2CreateOptions.class);
        actualCreateOptions.add(SMB2CreateOptions.FILE_DIRECTORY_FILE);
        actualCreateOptions.remove(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE);

        EnumSet<FileAttributes> actualAttributes = attributes != null ? EnumSet.copyOf(attributes) : EnumSet.noneOf(FileAttributes.class);
        actualAttributes.add(FILE_ATTRIBUTE_DIRECTORY);

        return (Directory) open(
            path,
            accessMask,
            actualAttributes,
            shareAccesses,
            createDisposition,
            actualCreateOptions
        );
    }

    public File openFile(String path, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        EnumSet<SMB2CreateOptions> actualCreateOptions = createOptions != null ? EnumSet.copyOf(createOptions) : EnumSet.noneOf(SMB2CreateOptions.class);
        actualCreateOptions.add(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE);
        actualCreateOptions.remove(SMB2CreateOptions.FILE_DIRECTORY_FILE);

        EnumSet<FileAttributes> actualAttributes = attributes != null ? EnumSet.copyOf(attributes) : EnumSet.noneOf(FileAttributes.class);
        actualAttributes.remove(FILE_ATTRIBUTE_DIRECTORY);

        return (File) open(
            path,
            accessMask,
            actualAttributes,
            shareAccesses,
            createDisposition,
            actualCreateOptions
        );
    }

    /**
     * File in the given path exists or not
     */
    public boolean fileExists(String path) throws SMBApiException {
        return exists(path, EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE));
    }

    /**
     * Folder in the given path exists or not.
     */
    public boolean folderExists(String path) throws SMBApiException {
        return exists(path, EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE));
    }

    private boolean exists(String path, EnumSet<SMB2CreateOptions> createOptions) throws SMBApiException {
        try (DiskEntry ignored = open(path, EnumSet.of(FILE_READ_ATTRIBUTES), EnumSet.of(FILE_ATTRIBUTE_NORMAL), ALL, FILE_OPEN, createOptions)) {
            return true;
        } catch (SMBApiException sae) {
            if (sae.getStatus() == NtStatus.STATUS_OBJECT_NAME_NOT_FOUND || sae.getStatus() == NtStatus.STATUS_OBJECT_PATH_NOT_FOUND) {
                return false;
            } else {
                throw sae;
            }
        }
    }

    /**
     * Equivalent to calling {@link #list(String, Class, String) list(path, FileIdBothDirectoryInformation.class, null)}.
     *
     * @see #list(String, Class, String)
     */
    public List<FileIdBothDirectoryInformation> list(String path) throws SMBApiException {
        return list(path, FileIdBothDirectoryInformation.class, null);
    }

    /**
     * Equivalent to calling {@link #list(String, Class, String) list(path, FileIdBothDirectoryInformation.class, searchPattern)}.
     *
     * @see #list(String, Class, String)
     */
    public List<FileIdBothDirectoryInformation> list(String path, String searchPattern) throws SMBApiException {
        return list(path, FileIdBothDirectoryInformation.class, searchPattern);
    }

    /**
     * Equivalent to calling {@link #list(String, Class, String) list(path, informationClass, null)}.
     *
     * @see #list(String, Class, String)
     */
    public <I extends FileDirectoryQueryableInformation> List<I> list(String path, Class<I> informationClass) {
        return list(path, informationClass, null);
    }

    /**
     * Opens the given path for read-only access and performs a directory listing.
     *
     * @see Directory#iterator(Class, String)
     */
    public <I extends FileDirectoryQueryableInformation> List<I> list(String path, Class<I> informationClass, String searchPattern) {
        try (Directory d = openDirectory(path, EnumSet.of(GENERIC_READ), null, ALL, FILE_OPEN, null)) {
            return d.list(informationClass, searchPattern);
        }
    }

    /**
     * Create a directory in the given path.
     */
    public void mkdir(String path) throws SMBApiException {
        Directory fileHandle = openDirectory(
            path,
            EnumSet.of(FILE_LIST_DIRECTORY, FILE_ADD_SUBDIRECTORY),
            EnumSet.of(FILE_ATTRIBUTE_DIRECTORY),
            ALL,
            FILE_CREATE,
            EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE));
        fileHandle.close();
    }

    /**
     * Get information about the given path.
     **/
    public FileAllInformation getFileInformation(String path) throws SMBApiException {
        return getFileInformation(path, FileAllInformation.class);
    }

    /**
     * Get information about the given path.
     **/
    public <F extends FileQueryableInformation> F getFileInformation(String path, Class<F> informationClass) throws SMBApiException {
        try (DiskEntry e = open(path, EnumSet.of(GENERIC_READ), null, ALL, FILE_OPEN, null)) {
            return e.getFileInformation(informationClass);
        }
    }

    /**
     * Get information for a given fileId
     **/
    public FileAllInformation getFileInformation(SMB2FileId fileId) throws SMBApiException, TransportException {
        return getFileInformation(fileId, FileAllInformation.class);
    }

    public <F extends FileQueryableInformation> F getFileInformation(SMB2FileId fileId, Class<F> informationClass) throws SMBApiException {
        FileInformation.Decoder<F> decoder = FileInformationFactory.getDecoder(informationClass);

        byte[] outputBuffer = queryInfo(
            fileId,
            SMB2QueryInfoRequest.SMB2QueryInfoType.SMB2_0_INFO_FILE,
            null,
            decoder.getInformationClass(),
            null
        ).getOutputBuffer();

        try {
            return decoder.read(new Buffer.PlainBuffer(outputBuffer, Endian.LE));
        } catch (Buffer.BufferException e) {
            throw new SMBRuntimeException(e);
        }
    }

    public <F extends FileSettableInformation> void setFileInformation(SMB2FileId fileId, F information) {
        SMBBuffer buffer = new SMBBuffer();
        FileInformation.Encoder<F> encoder = FileInformationFactory.getEncoder(information);
        encoder.write(information, buffer);

        setInfo(
            fileId,
            SMB2SetInfoRequest.SMB2InfoType.SMB2_0_INFO_FILE,
            null,
            encoder.getInformationClass(),
            buffer.getCompactData()
        );
    }

    /**
     * Get information for a given path
     **/
    public <F extends FileSettableInformation> void setFileInformation(String path, F information) throws SMBApiException {
        try (DiskEntry e = open(path, EnumSet.of(GENERIC_WRITE), null, ALL, FILE_OPEN, null)) {
            e.setFileInformation(information);
        }
    }

    /**
     * Get Share Information for the current Disk Share
     *
     * @return the ShareInfo
     */
    public ShareInfo getShareInformation() throws SMBApiException {
        try (Directory directory = openDirectory("", EnumSet.of(FILE_READ_ATTRIBUTES), null, ALL, FILE_OPEN, null)) {
            byte[] outputBuffer = queryInfo(
                directory.getFileId(),
                SMB2QueryInfoRequest.SMB2QueryInfoType.SMB2_0_INFO_FILESYSTEM,
                null,
                null,
                FileSystemInformationClass.FileFsFullSizeInformation
            ).getOutputBuffer();

            try {
                return ShareInfo.parseFsFullSizeInformation(new Buffer.PlainBuffer(outputBuffer, Endian.LE));
            } catch (Buffer.BufferException e) {
                throw new SMBRuntimeException(e);
            }
        }
    }

    /**
     * Remove the directory at the given path.
     */
    public void rmdir(String path, boolean recursive) throws SMBApiException {
        if (recursive) {
            List<FileIdBothDirectoryInformation> list = list(path);
            for (FileIdBothDirectoryInformation fi : list) {
                if (fi.getFileName().equals(".") || fi.getFileName().equals("..")) {
                    continue;
                }
                String childPath = path + "\\" + fi.getFileName();
                if (!EnumWithValue.EnumUtils.isSet(fi.getFileAttributes(), FILE_ATTRIBUTE_DIRECTORY)) {
                    rm(childPath);
                } else {
                    rmdir(childPath, true);
                }
            }
            rmdir(path, false);
        } else {
            try (DiskEntry e = open(
                path,
                EnumSet.of(DELETE),
                EnumSet.of(FILE_ATTRIBUTE_DIRECTORY),
                EnumSet.of(FILE_SHARE_DELETE, FILE_SHARE_WRITE, FILE_SHARE_READ),
                FILE_OPEN,
                EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE)
            )) {
                e.deleteOnClose();
            }
        }
    }

    /**
     * Remove the file at the given path
     */
    public void rm(String path) throws SMBApiException {
        try (DiskEntry e = open(
            path,
            EnumSet.of(DELETE),
            EnumSet.of(FILE_ATTRIBUTE_NORMAL),
            EnumSet.of(FILE_SHARE_DELETE, FILE_SHARE_WRITE, FILE_SHARE_READ),
            FILE_OPEN,
            EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE)
        )) {
            e.deleteOnClose();
        }
    }

    public void deleteOnClose(SMB2FileId fileId) {
        setFileInformation(fileId, new FileDispositionInformation(true));
    }

    /**
     * The SecurityDescriptor(MS-DTYP 2.4.6 SECURITY_DESCRIPTOR) for the Given Path
     */
    public SecurityDescriptor getSecurityInfo(String path, Set<SecurityInformation> securityInfo) throws SMBApiException {
        EnumSet<AccessMask> accessMask = EnumSet.of(GENERIC_READ);
        if (securityInfo.contains(SecurityInformation.SACL_SECURITY_INFORMATION)) {
            accessMask.add(ACCESS_SYSTEM_SECURITY);
        }

        try (DiskEntry e = open(path, accessMask, null, ALL, FILE_OPEN, null)) {
            return e.getSecurityInformation(securityInfo);
        }
    }

    /**
     * The SecurityDescriptor(MS-DTYP 2.4.6 SECURITY_DESCRIPTOR) for the Given FileId
     */
    public SecurityDescriptor getSecurityInfo(SMB2FileId fileId, Set<SecurityInformation> securityInfo) throws SMBApiException {

        byte[] outputBuffer = queryInfo(fileId, SMB2_0_INFO_SECURITY, securityInfo, null, null).getOutputBuffer();
        try {
            return SecurityDescriptor.read(new SMBBuffer(outputBuffer));
        } catch (Buffer.BufferException e) {
            throw new SMBRuntimeException(e);
        }
    }

    /**
     * The SecurityDescriptor(MS-DTYP 2.4.6 SECURITY_DESCRIPTOR) for the Given FileId
     */
    public void setSecurityInfo(String path, Set<SecurityInformation> securityInfo, SecurityDescriptor securityDescriptor) throws SMBApiException {
        Set<AccessMask> accessMask = EnumSet.of(GENERIC_WRITE);
        if (securityInfo.contains(SecurityInformation.SACL_SECURITY_INFORMATION)) {
            accessMask.add(ACCESS_SYSTEM_SECURITY);
        }
        if (securityInfo.contains(SecurityInformation.OWNER_SECURITY_INFORMATION)) {
            accessMask.add(WRITE_OWNER);
        }
        if (securityInfo.contains(SecurityInformation.DACL_SECURITY_INFORMATION)) {
            accessMask.add(WRITE_DAC);
        }

        try (DiskEntry e = open(path, accessMask, null, ALL, FILE_OPEN, null)) {
            e.setSecurityInformation(securityDescriptor, securityInfo);
        }
    }

    /**
     * The SecurityDescriptor(MS-DTYP 2.4.6 SECURITY_DESCRIPTOR) for the Given FileId
     */
    public void setSecurityInfo(SMB2FileId fileId, Set<SecurityInformation> securityInfo, SecurityDescriptor securityDescriptor) throws SMBApiException {
        SMBBuffer buffer = new SMBBuffer();
        securityDescriptor.write(buffer);

        setInfo(
            fileId,
            SMB2SetInfoRequest.SMB2InfoType.SMB2_0_INFO_SECURITY,
            securityInfo,
            null,
            buffer.getCompactData()
        );
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getSmbPath() + "]";
    }
}
