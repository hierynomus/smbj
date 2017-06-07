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

import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.Future;

import com.hierynomus.msfscc.fileinformation.FileBasicInformationEnum;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.hierynomus.msdtyp.FileTime;
import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.SecurityDescriptor;
import com.hierynomus.msdtyp.SecurityInformation;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.FileInformationClass;
import com.hierynomus.msfscc.FileSystemInformationClass;
import com.hierynomus.msfscc.fileinformation.FileInfo;
import com.hierynomus.msfscc.fileinformation.FileInformationFactory;
import com.hierynomus.msfscc.fileinformation.ShareInfo;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.mssmb2.messages.*;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.TransportException;

import static com.hierynomus.msdtyp.AccessMask.FILE_READ_ATTRIBUTES;
import static com.hierynomus.msdtyp.AccessMask.GENERIC_READ;
import static com.hierynomus.msdtyp.AccessMask.GENERIC_WRITE;
import static com.hierynomus.msfscc.FileAttributes.FILE_ATTRIBUTE_DIRECTORY;
import static com.hierynomus.msfscc.FileAttributes.FILE_ATTRIBUTE_NORMAL;
import static com.hierynomus.mssmb2.SMB2ShareAccess.EnumUtils;
import static com.hierynomus.mssmb2.SMB2ShareAccess.FILE_SHARE_DELETE;
import static com.hierynomus.mssmb2.SMB2ShareAccess.FILE_SHARE_READ;
import static com.hierynomus.mssmb2.SMB2ShareAccess.FILE_SHARE_WRITE;
import static com.hierynomus.mssmb2.messages.SMB2QueryInfoRequest.SMB2QueryInfoType.SMB2_0_INFO_SECURITY;
import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toLong;

public class DiskShare extends Share {

    private static final Logger logger = LoggerFactory.getLogger(DiskShare.class);

    public DiskShare(SmbPath smbPath, TreeConnect treeConnect) {
        super(smbPath, treeConnect);
    }

    /**
     * Get a listing the given directory path. The "." and ".." are pre-filtered.
     */
    public List<FileInfo> list(String path) throws SMBApiException, TransportException {
        logger.info("List {}", path);

        Directory fileHandle = openDirectory(path, EnumSet.of(GENERIC_READ),
            EnumSet.of(FILE_SHARE_DELETE, FILE_SHARE_WRITE, FILE_SHARE_READ), SMB2CreateDisposition.FILE_OPEN);

        try {
            return fileHandle.list();
        } finally {
            if (fileHandle != null) {
                fileHandle.closeSilently();
            }
        }
    }

    public DiskEntry getFile(String path) {
        try {
            FileInfo fileInformation = getFileInformation(path);
            EnumSet<FileAttributes> fileAttributes = EnumUtils.toEnumSet(fileInformation.getFileAttributes(), FileAttributes.class);
            if (fileAttributes.contains(FILE_ATTRIBUTE_DIRECTORY)) {
                return new Directory(null, treeConnect, path);
            } else {
                return new File(null, treeConnect, path, fileInformation.getAccessMask());
            }
        } catch (SMBApiException ex) {
//            if (ex.getStatus() == NtStatus.STATUS_OBJECT_NAME_NOT_FOUND) {
//                return new NonExisting(null, treeConnect, path);
//            }
            throw ex;
        }
    }

    /**
     * Get a handle to a directory in the given path
     */
    public Directory openDirectory(
        String path,
        EnumSet<AccessMask> accessMask,
        EnumSet<SMB2ShareAccess> shareAccess,
        SMB2CreateDisposition createDisposition) throws TransportException, SMBApiException {
        logger.info("OpenDirectory {},{},{},{},{}", path, accessMask, shareAccess, createDisposition);

        SMB2FileId fileId = open(path, toLong(accessMask), EnumSet.of(FILE_ATTRIBUTE_DIRECTORY), shareAccess, createDisposition, EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE));
        return new Directory(fileId, treeConnect, path);

    }

    /**
     * Get a handle to a file
     */
    public File openFile(String path, EnumSet<AccessMask> accessMask, SMB2CreateDisposition createDisposition) throws TransportException, SMBApiException {
        logger.info("OpenFile {},{},{}", path, accessMask, createDisposition);

        long accessMaskValue = toLong(accessMask);
        SMB2FileId fileId = open(path, accessMaskValue, null, EnumSet.of(FILE_SHARE_READ), createDisposition, EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE));
        // TODO
        return new File(fileId, treeConnect, path, accessMaskValue);
    }

    /**
     * File in the given path exists or not
     */
    public boolean fileExists(String path) throws SMBApiException {
        logger.info("file exists {}", path);
        return exists(path, EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE));
    }

    /**
     * Folder in the given path exists or not.
     */
    public boolean folderExists(String path) throws SMBApiException {
        logger.info("Checking existence of Directory '{}' on {}", path, smbPath);
        return exists(path, EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE));
    }

    /**
     * Create a directory in the given path.
     */
    public void mkdir(String path) throws TransportException, SMBApiException {
        logger.info("mkdir {}", path);

        Directory fileHandle = openDirectory(path,
            EnumSet.of(AccessMask.FILE_LIST_DIRECTORY, AccessMask.FILE_ADD_SUBDIRECTORY),
            EnumSet.of(FILE_SHARE_DELETE, FILE_SHARE_WRITE,
                FILE_SHARE_READ),
            SMB2CreateDisposition.FILE_CREATE);

        fileHandle.close();

    }

    /**
     * Get information about the given path.
     **/
    public FileInfo getFileInformation(String path) throws SMBApiException {

        byte[] outputBuffer = queryInfoCommon(path,
            SMB2QueryInfoRequest.SMB2QueryInfoType.SMB2_0_INFO_FILE, null,
            FileInformationClass.FileAllInformation);

        try {
            return FileInformationFactory.parseFileAllInformation(
                new Buffer.PlainBuffer(outputBuffer, Endian.LE));
        } catch (Buffer.BufferException e) {
            throw new SMBRuntimeException(e);
        }
    }

    /**
     * Get information for a given fileId
     **/
    public FileInfo getFileInformation(SMB2FileId fileId) throws SMBApiException, TransportException {

        byte[] outputBuffer = queryInfoCommon(fileId,
            SMB2QueryInfoRequest.SMB2QueryInfoType.SMB2_0_INFO_FILE, null,
            FileInformationClass.FileAllInformation);

        try {
            return FileInformationFactory.parseFileAllInformation(
                new Buffer.PlainBuffer(outputBuffer, Endian.LE));
        } catch (Buffer.BufferException e) {
            throw new TransportException(e);
        }
    }

    /**
     * Get Share Information for the current Disk Share
     * 
     * @return the ShareInfo
     * @throws SMBApiException
     */
    public ShareInfo getShareInformation() throws TransportException, SMBApiException {

        Directory directory = openDirectory("",
                EnumSet.of(FILE_READ_ATTRIBUTES), 
                EnumSet.of(FILE_SHARE_DELETE, FILE_SHARE_WRITE, FILE_SHARE_READ),
                SMB2CreateDisposition.FILE_OPEN);

        byte[] outputBuffer = queryInfoCommon(directory.getFileId(),
                SMB2QueryInfoRequest.SMB2QueryInfoType.SMB2_0_INFO_FILESYSTEM, null, null,
                FileSystemInformationClass.FileFsFullSizeInformation);

        try {
            return ShareInfo.parseFsFullSizeInformation(new Buffer.PlainBuffer(outputBuffer, Endian.LE));
        } catch (Buffer.BufferException e) {
            throw new SMBRuntimeException(e);
        }
    }
    
    /**
     * Remove the directory at the given path.
     */
    public void rmdir(String path, boolean recursive) throws TransportException, SMBApiException {
        logger.info("rmdir {},{}", path, recursive);

        //TODO Even with DELETE_CHILD permission, receiving error, so doing the recursive way for now.
        //if (recursive) accessMask.add(SMB2DirectoryAccessMask.FILE_DELETE_CHILD);
        if (recursive) {
            List<FileInfo> list = list(path);
            for (FileInfo fi : list) {
                if (!EnumWithValue.EnumUtils.isSet(fi.getFileAttributes(), FILE_ATTRIBUTE_DIRECTORY)) {
                    rm(makePath(path, fi.getFileName()));
                } else {
                    rmdir(makePath(path, fi.getFileName()), recursive);
                }
            }
            rmdir(path, false);
        } else {

            SMB2CreateRequest smb2CreateRequest =
                openFileRequest(treeConnect, path,
                    AccessMask.DELETE.getValue(),
                    EnumSet.of(FILE_SHARE_DELETE, FILE_SHARE_WRITE,
                        FILE_SHARE_READ),
                    EnumSet.of(FILE_ATTRIBUTE_DIRECTORY),
                    SMB2CreateDisposition.FILE_OPEN,
                    null);

            deleteCommon(path, smb2CreateRequest);
        }
    }

    /**
     * Remove the file at the given path
     */
    public void rm(String path) throws TransportException, SMBApiException {
        logger.info("rm {}", path);
        SMB2CreateRequest smb2CreateRequest =
            openFileRequest(treeConnect, path, AccessMask.DELETE.getValue(), null, null,
                SMB2CreateDisposition.FILE_OPEN, EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE));

        deleteCommon(path, smb2CreateRequest);
    }

//    /**
//     * Write the given input stream to the given path
//     */
//    public void write(String path, boolean overWrite,
//                             InputStream srcStream, ProgressListener progressListener)
//            throws SMBApiException, IOException {
//        logger.info("Write {},{}", path, overWrite);
//        SMB2CreateDisposition createDisposition = SMB2CreateDisposition.FILE_OVERWRITE_IF;
//        if (!overWrite) createDisposition = SMB2CreateDisposition.FILE_CREATE;
//        File fileHandle =
//                openFile(path, EnumSet.of(AccessMask.GENERIC_WRITE), createDisposition);
//
//        try {
//            fileHandle.write(srcStream, progressListener);
//        } finally {
//            fileHandle.close();
//        }
//    }
//
//    /**
//     * Read the file at the given path and write the data to the given output stream
//     */
//    public void read(String path,
//                            OutputStream destStream, ProgressListener progressListener)
//            throws SMBApiException, IOException {
//        logger.info("Read {}", path);
//        File fileHandle = openFile(path,
//                EnumSet.of(AccessMask.GENERIC_READ), SMB2CreateDisposition.FILE_OPEN);
//
//        try {
//            fileHandle.read(destStream, progressListener);
//        } finally {
//            fileHandle.close();
//        }
//    }

    /**
     * The SecurityDescriptor(MS-DTYP 2.4.6 SECURITY_DESCRIPTOR) for the Given Path
     */
    public SecurityDescriptor getSecurityInfo(String path, EnumSet<SecurityInformation> securityInfo) throws SMBApiException, TransportException {

        byte[] outputBuffer = queryInfoCommon(path,
            SMB2_0_INFO_SECURITY, securityInfo, null);
        SecurityDescriptor sd = new SecurityDescriptor();
        try {
            sd.read(new SMBBuffer(outputBuffer));
        } catch (Buffer.BufferException e) {
            throw new TransportException(e);
        }
        return sd;
    }

    /**
     * The SecurityDescriptor(MS-DTYP 2.4.6 SECURITY_DESCRIPTOR) for the Given FileId
     */
    public SecurityDescriptor getSecurityInfo(SMB2FileId fileId, EnumSet<SecurityInformation> securityInfo) throws SMBApiException, TransportException {

        byte[] outputBuffer = queryInfoCommon(fileId, SMB2_0_INFO_SECURITY, securityInfo, null);
        SecurityDescriptor sd = new SecurityDescriptor();
        try {
            sd.read(new SMBBuffer(outputBuffer));
        } catch (Buffer.BufferException e) {
            throw new TransportException(e);
        }
        return sd;
    }


    private String makePath(String first, String... more) {
        StringBuilder sb = new StringBuilder(first);
        for (int i = 0; i < more.length; i++) {
            sb.append('\\');
            sb.append(more[i]);
        }
        return sb.toString();
    }

    private void deleteCommon(String path, SMB2CreateRequest smb2CreateRequest)
        throws TransportException, SMBApiException {

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        // TODO Use Compounding
        Future<SMB2CreateResponse> sendFuture = session.send(smb2CreateRequest);
        SMB2CreateResponse response = Futures.get(sendFuture, TransportException.Wrapper);

        if (response.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(response.getHeader(), "Create failed for " + path);
        }

        SMB2FileId fileId = response.getFileId();
        try {
            byte[] dispoInfo = FileInformationFactory.getFileDispositionInfo(true);
            SMB2SetInfoRequest si_req = new SMB2SetInfoRequest(
                connection.getNegotiatedProtocol().getDialect(), session.getSessionId(), treeConnect.getTreeId(),
                SMB2SetInfoRequest.SMB2InfoType.SMB2_0_INFO_FILE, fileId,
                FileInformationClass.FileDispositionInformation, null, dispoInfo);

            Future<SMB2SetInfoResponse> setInfoFuture = session.send(si_req);
            SMB2SetInfoResponse setInfoResponse = Futures.get(setInfoFuture, TransportException.Wrapper);

            if (setInfoResponse.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                throw new SMBApiException(setInfoResponse.getHeader(), "SetInfo failed for " + path);
            }
        } finally {
            SMB2Close closeReq = new SMB2Close(connection.getNegotiatedProtocol().getDialect(),
                session.getSessionId(), treeConnect.getTreeId(), fileId);
            Future<SMB2Close> closeFuture = session.send(closeReq);
            SMB2Close closeResponse = Futures.get(closeFuture, TransportException.Wrapper);

            if (closeResponse.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                throw new SMBApiException(closeResponse.getHeader(), "Close failed for " + path);
            }

        }
    }

    public boolean exists(String path, EnumSet<SMB2CreateOptions> createOptions) throws SMBApiException {
        logger.info("exists {}", path);

        SMB2FileId fileId = null;
        try {
            fileId = open(path, toLong(EnumSet.of(FILE_READ_ATTRIBUTES)), EnumSet.of(FILE_ATTRIBUTE_DIRECTORY),
                EnumSet.of(FILE_SHARE_DELETE, FILE_SHARE_WRITE, FILE_SHARE_READ), SMB2CreateDisposition.FILE_OPEN, createOptions);
            return true;
        } catch (SMBApiException sae) {
            if (sae.getStatus() == NtStatus.STATUS_OBJECT_NAME_NOT_FOUND) {
                return false;
            } else {
                throw sae;
            }
        } finally {
            if (fileId != null) {
                try {
                    close(fileId);
                } catch (Exception e) {
                    logger.warn("File close failed for {},{},{}", path, treeConnect, fileId, e);
                }
            }
        }
    }

    private byte[] queryInfoCommon(
        String path,
        SMB2QueryInfoRequest.SMB2QueryInfoType infoType,
        EnumSet<SecurityInformation> securityInfo,
        FileInformationClass fileInformationClass)
        throws SMBApiException {

        SMB2FileId fileId = null;
        try {
            fileId = open(path, toLong(EnumSet.of(GENERIC_READ)), EnumSet.of(FILE_ATTRIBUTE_NORMAL),
                EnumSet.of(FILE_SHARE_DELETE, FILE_SHARE_WRITE, FILE_SHARE_READ), SMB2CreateDisposition.FILE_OPEN, null);
            return queryInfoCommon(fileId, infoType, securityInfo, fileInformationClass);
        } finally {
            if (fileId != null) {
                try {
                    close(fileId);
                } catch (Exception e) {
                    logger.warn("File close failed for {},{},{}", path, treeConnect, fileId, e);
                }
            }
        }
    }

    private byte[] queryInfoCommon(
            SMB2FileId fileId,
            SMB2QueryInfoRequest.SMB2QueryInfoType infoType,
            EnumSet<SecurityInformation> securityInfo,
            FileInformationClass fileInformationClass)
            throws SMBApiException {
    	return queryInfoCommon(fileId, infoType, securityInfo, fileInformationClass, null);
    }
    
    private byte[] queryInfoCommon(
        SMB2FileId fileId,
        SMB2QueryInfoRequest.SMB2QueryInfoType infoType,
        EnumSet<SecurityInformation> securityInfo,
        FileInformationClass fileInformationClass,
        FileSystemInformationClass fileSystemInformationClass)
        throws SMBApiException {

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        SMB2QueryInfoRequest qreq = new SMB2QueryInfoRequest(
            connection.getNegotiatedProtocol().getDialect(), session.getSessionId(), treeConnect.getTreeId(),
            fileId, infoType,
            fileInformationClass, fileSystemInformationClass, null, securityInfo);
        try {
            Future<SMB2QueryInfoResponse> qiResponseFuture = session.send(qreq);
            SMB2QueryInfoResponse qresp = Futures.get(qiResponseFuture, SMBRuntimeException.Wrapper);

            if (qresp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                throw new SMBApiException(qresp.getHeader(), "QUERY_INFO failed for " + fileId);
            }
            return qresp.getOutputBuffer();
        } catch (TransportException e) {
            throw SMBRuntimeException.Wrapper.wrap(e);
        }
    }

    public void setCreationTime(String path, FileTime creationTime)throws SMBApiException, TransportException{
        this.setBasicInformationTime(path, creationTime, FileBasicInformationEnum.CreationTime);
    }

    public void setCreationTime(SMB2FileId fileId, FileTime creationTime)throws SMBApiException, TransportException {
        this.setBasicInformationTime(fileId, creationTime, FileBasicInformationEnum.CreationTime);
    }

    public void setLastAccessTime(String path, FileTime lastAccessTime)throws SMBApiException, TransportException{
        this.setBasicInformationTime(path, lastAccessTime, FileBasicInformationEnum.LastAccessTime);
    }

    public void setLastAccessTime(SMB2FileId fileId, FileTime lastAccessTime)throws SMBApiException, TransportException {
        this.setBasicInformationTime(fileId, lastAccessTime, FileBasicInformationEnum.LastAccessTime);
    }

    public void setLastWriteTime(String path, FileTime lastWriteTime)throws SMBApiException, TransportException{
        this.setBasicInformationTime(path, lastWriteTime, FileBasicInformationEnum.LastWriteTime);
    }

    public void setLastWriteTime(SMB2FileId fileId, FileTime lastWriteTime)throws SMBApiException, TransportException {
        this.setBasicInformationTime(fileId, lastWriteTime, FileBasicInformationEnum.LastWriteTime);
    }

    public void setChangeTime(String path, FileTime changeTime)throws SMBApiException, TransportException{
        this.setBasicInformationTime(path, changeTime, FileBasicInformationEnum.ChangeTime);
    }

    public void setChangeTime(SMB2FileId fileId, FileTime changeTime)throws SMBApiException, TransportException {
        this.setBasicInformationTime(fileId, changeTime, FileBasicInformationEnum.ChangeTime);
    }

    public void setBasicInformationTime(
        String path,
        FileTime timetoSet,
        FileBasicInformationEnum basicInfoClass)
        throws SMBApiException, TransportException {

        SMB2CreateRequest smb2CreateRequest =
            openFileRequest(treeConnect, path, toLong(EnumSet.of(GENERIC_WRITE)), null, null,
                SMB2CreateDisposition.FILE_OPEN, null);

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        Future<SMB2CreateResponse> sendFuture = session.send(smb2CreateRequest);
        SMB2CreateResponse response = Futures.get(sendFuture, TransportException.Wrapper);

        if (response.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(response.getHeader(), "Create failed for " + path);
        }

        SMB2FileId fileId = response.getFileId();

        try {
            this.setBasicInformationTime(fileId,
                timetoSet,
                basicInfoClass);
        } finally {
            // close the file because we opened it in this function
            SMB2Close closeReq = new SMB2Close(connection.getNegotiatedProtocol().getDialect(),
                session.getSessionId(), treeConnect.getTreeId(), fileId);
            Future<SMB2Close> closeFuture = session.send(closeReq);
            SMB2Close closeResponse = Futures.get(closeFuture, TransportException.Wrapper);

            if (closeResponse.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                throw new SMBApiException(closeResponse.getHeader(), "Close failed for " + fileId.toString());
            }
        }

    }

    public void setBasicInformationTime(
        SMB2FileId fileId,
        FileTime timeToSet,
        FileBasicInformationEnum timeClass)
        throws SMBApiException, TransportException {

        if(timeClass == FileBasicInformationEnum.FileAttributes) {
            logger.info("Input data mismatch the class to set!" + " SetInfo failed for " + fileId.toString());
        }

        try {
            byte[] basicInfo = FileInformationFactory.getFileBasicInfo(
                timeToSet,
                timeClass
            );

            setInfoCommon(fileId,
                SMB2SetInfoRequest.SMB2InfoType.SMB2_0_INFO_FILE,
                null,
                FileInformationClass.FileBasicInformation,
                basicInfo);

        } catch (Buffer.BufferException e) {
            throw new SMBRuntimeException(e);
        }

    }

    public void setAttributes(
        String path,
        EnumSet<FileAttributes> fileAttributes)
        throws SMBApiException, TransportException {

        SMB2CreateRequest smb2CreateRequest =
            openFileRequest(treeConnect, path, toLong(EnumSet.of(GENERIC_WRITE)), null, null,
                SMB2CreateDisposition.FILE_OPEN, null);

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        Future<SMB2CreateResponse> sendFuture = session.send(smb2CreateRequest);
        SMB2CreateResponse response = Futures.get(sendFuture, TransportException.Wrapper);

        if (response.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(response.getHeader(), "Create failed for " + path);
        }

        SMB2FileId fileId = response.getFileId();

        try {
            this.setAttributes(fileId, fileAttributes);
        } finally {
            // close the file because we opened it in this function
            SMB2Close closeReq = new SMB2Close(connection.getNegotiatedProtocol().getDialect(),
                session.getSessionId(), treeConnect.getTreeId(), fileId);
            Future<SMB2Close> closeFuture = session.send(closeReq);
            SMB2Close closeResponse = Futures.get(closeFuture, TransportException.Wrapper);

            if (closeResponse.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                throw new SMBApiException(closeResponse.getHeader(), "Close failed for " + fileId.toString());
            }
        }

    }

    public void setAttributes(
        SMB2FileId fileId,
        EnumSet<FileAttributes> fileAttributes)
        throws SMBApiException, TransportException {

        try {
            byte[] basicInfo = FileInformationFactory.getFileBasicInfo(
                toLong(fileAttributes)
            );

            setInfoCommon(fileId,
                SMB2SetInfoRequest.SMB2InfoType.SMB2_0_INFO_FILE,
                null,
                FileInformationClass.FileBasicInformation,
                basicInfo);

        } catch (Buffer.BufferException e) {
            throw new SMBRuntimeException(e);
        }

    }

    /***
     * Set the BasicFileInformtion for the file/directory with the path. This function will open the file by itself. After finsih, it will close the file back.
     * @param path path of the target file/directory.
     * @param creationTime the creation time to set
     * @param lastAccessTime the last access time to set
     * @param lastWriteTime the last write time to set
     * @param changeTime the change time to set
     * @param fileAttributes the attributes to set
     * @throws SMBApiException
     * @throws TransportException
     */
    public void setBasicFileInformation(
        String path,
        FileTime creationTime,
        FileTime lastAccessTime,
        FileTime lastWriteTime,
        FileTime changeTime,
        long fileAttributes)
        throws SMBApiException, TransportException {

        SMB2CreateRequest smb2CreateRequest =
            openFileRequest(treeConnect, path, toLong(EnumSet.of(GENERIC_WRITE)), null, null,
                SMB2CreateDisposition.FILE_OPEN, null);

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        Future<SMB2CreateResponse> sendFuture = session.send(smb2CreateRequest);
        SMB2CreateResponse response = Futures.get(sendFuture, TransportException.Wrapper);

        if (response.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(response.getHeader(), "Create failed for " + path);
        }

        SMB2FileId fileId = response.getFileId();

        try {

            setBasicFileInformation(
                fileId,
                creationTime,
                lastAccessTime,
                lastWriteTime,
                changeTime,
                fileAttributes
            );

        } finally {
            // close the file because we opened it in this function
            SMB2Close closeReq = new SMB2Close(connection.getNegotiatedProtocol().getDialect(),
                session.getSessionId(), treeConnect.getTreeId(), fileId);
            Future<SMB2Close> closeFuture = session.send(closeReq);
            SMB2Close closeResponse = Futures.get(closeFuture, TransportException.Wrapper);

            if (closeResponse.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                throw new SMBApiException(closeResponse.getHeader(), "Close failed for " + fileId.toString());
            }
        }

    }

    /***
     * Set the BasicFileInformtion for the file/directory with the fileId
     * @param fileId fileId (file handle) of the target file/directory.
     * @param creationTime the creation time to set
     * @param lastAccessTime the last access time to set
     * @param lastWriteTime the last write time to set
     * @param changeTime the change time to set
     * @param fileAttributes the attributes to set
     * @throws SMBApiException
     * @throws TransportException
     */
    public void setBasicFileInformation(
        SMB2FileId fileId,
        FileTime creationTime,
        FileTime lastAccessTime,
        FileTime lastWriteTime,
        FileTime changeTime,
        long fileAttributes)
        throws SMBApiException, TransportException {

        try {

            byte[] basicInfo = FileInformationFactory.getFileBasicInfo(
                creationTime,
                lastAccessTime,
                lastWriteTime,
                changeTime,
                fileAttributes
            );

            setInfoCommon(fileId,
                SMB2SetInfoRequest.SMB2InfoType.SMB2_0_INFO_FILE,
                null,
                FileInformationClass.FileBasicInformation,
                basicInfo);

        } catch (Buffer.BufferException e) {
            throw new SMBRuntimeException(e);
        }
    }

    /***
     * Send the SMB2SetInfoRequest with the input message the information class.
     * @param fileId fileId (file handle) of the target file/directory.
     * @param infoType The info type of SMB2SetInfoRequest, e.g. SMB2_0_INFO_FILE, SMB2_0_INFO_FILESYSTEM, SMB2_0_INFO_SECURITY, etc.
     * @param securityInfo The security Info when sending SMB2_0_INFO_SECURITY. E.g. OWNER_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION.
     * @param fileInformationClass the class of the setting information, e.g. FileBasicInformation, FileRenameInformation, etc.
     * @param buffer the pre-built message for the specific class of the setting information.
     * @throws TransportException
     * @throws SMBApiException
     */
    private void setInfoCommon(
        SMB2FileId fileId,
        SMB2SetInfoRequest.SMB2InfoType infoType,
        EnumSet<SecurityInformation> securityInfo,
        FileInformationClass fileInformationClass,
        byte[] buffer)
        throws TransportException, SMBApiException {

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        SMB2SetInfoRequest setInfoRequest = new SMB2SetInfoRequest(connection.getNegotiatedProtocol().getDialect(),
            session.getSessionId(),
            treeConnect.getTreeId(),
            infoType,
            fileId,
            fileInformationClass,
            securityInfo,
            buffer);

        Future<SMB2SetInfoResponse> sendInfoFuture = session.send(setInfoRequest);
        SMB2SetInfoResponse setInfoResponse = Futures.get(sendInfoFuture, TransportException.Wrapper);

        if (setInfoResponse.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(setInfoResponse.getHeader(), "SetInfo failed for " + fileId.toString());
        }

    }

    public boolean checkAccessMask(AccessMask mask, String smbPathOnShare) {
        File file = null;
        try {
            file = openFile(smbPathOnShare, EnumSet.of(mask), SMB2CreateDisposition.FILE_OPEN);
            return file != null;
        } catch (TransportException e) {
            throw new IllegalStateException("Exception occurred while trying to determine permissions on file", e);
        } catch (SMBApiException e) {
            return checkPermissions(e);
        } finally {
            close(file);
        }
    }

    private boolean checkPermissions(SMBApiException e) {
        if (e.getStatus().equals(NtStatus.STATUS_ACCESS_DENIED)) {
            return false;
        }
        throw e;
    }

    private void close(File file) {
        try {
            close(file.getFileId());
        } catch (TransportException e) {
            throw new IllegalStateException("Exception occured while trying to determine permissions on file", e);
        }
    }
}
