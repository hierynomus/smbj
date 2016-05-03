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
package com.hierynomus.smbj;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.SecurityDescriptor;
import com.hierynomus.msdtyp.SecurityInformation;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.FileInformationClass;
import com.hierynomus.msfscc.fileinformation.FileInfo;
import com.hierynomus.msfscc.fileinformation.FileInformationFactory;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.TreeConnect;
import com.hierynomus.smbj.smb2.SMB2CompletionFilter;
import com.hierynomus.smbj.smb2.SMB2CreateDisposition;
import com.hierynomus.smbj.smb2.SMB2CreateOptions;
import com.hierynomus.smbj.smb2.SMB2FileId;
import com.hierynomus.smbj.smb2.SMB2ShareAccess;
import com.hierynomus.smbj.smb2.messages.SMB2ChangeNotifyRequest;
import com.hierynomus.smbj.smb2.messages.SMB2ChangeNotifyResponse;
import com.hierynomus.smbj.smb2.messages.SMB2Close;
import com.hierynomus.smbj.smb2.messages.SMB2CreateRequest;
import com.hierynomus.smbj.smb2.messages.SMB2CreateResponse;
import com.hierynomus.smbj.smb2.messages.SMB2QueryDirectoryRequest;
import com.hierynomus.smbj.smb2.messages.SMB2QueryDirectoryResponse;
import com.hierynomus.smbj.smb2.messages.SMB2QueryInfoRequest;
import com.hierynomus.smbj.smb2.messages.SMB2QueryInfoResponse;
import com.hierynomus.smbj.smb2.messages.SMB2ReadRequest;
import com.hierynomus.smbj.smb2.messages.SMB2ReadResponse;
import com.hierynomus.smbj.smb2.messages.SMB2SetInfoRequest;
import com.hierynomus.smbj.smb2.messages.SMB2SetInfoResponse;
import com.hierynomus.smbj.smb2.messages.SMB2WriteRequest;
import com.hierynomus.smbj.smb2.messages.SMB2WriteResponse;
import com.hierynomus.smbj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.Future;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toLong;

/**
 * Provides operations on already open file and also static methods for open/op/close
 * <p>
 * MS-SMB2.pdf 3.2.1.6 Per Application Open of a File
 */
public class SMBFile {

    private static final Logger logger = LoggerFactory.getLogger(SMBFile.class);

    SMB2FileId fileId;
    TreeConnect treeConnect;
    String fileName;

    EnumSet<AccessMask> accessMask; // The Access the current user has on the file.
    EnumSet<SMB2ShareAccess> shareAccess;
    EnumSet<SMB2CreateOptions> createOptions;
    EnumSet<FileAttributes> fileAttributes;
    SMB2CreateDisposition createDisposition;

    public SMBFile(
            SMB2FileId fileId, TreeConnect treeConnect, String fileName, EnumSet<AccessMask> accessMask,
            EnumSet<SMB2ShareAccess> shareAccess, EnumSet<SMB2CreateOptions> createOptions,
            EnumSet<FileAttributes> fileAttributes, SMB2CreateDisposition createDisposition) {
        this.fileId = fileId;
        this.treeConnect = treeConnect;
        this.fileName = fileName;
        this.accessMask = accessMask;
        this.shareAccess = shareAccess;
        this.createOptions = createOptions;
        this.fileAttributes = fileAttributes;
        this.createDisposition = createDisposition;
    }

    /**
     * Get a listing the given directory path. The "." and ".." are pre-filtered.
     */
    public static List<FileInfo> list(TreeConnect treeConnect, String path)
            throws SMBApiException, TransportException {
        logger.info("List {}", path);

        SMBFile fileHandle = openDirectory(treeConnect, path,
                EnumSet.of(AccessMask.GENERIC_READ),
                EnumSet.of(SMB2ShareAccess.FILE_SHARE_DELETE, SMB2ShareAccess.FILE_SHARE_WRITE, SMB2ShareAccess
                        .FILE_SHARE_READ),
                SMB2CreateDisposition.FILE_OPEN);

        try {
            return fileHandle.list();
        } finally {
            if (fileHandle != null) {
                fileHandle.closeSilently();
            }
        }
    }

    /**
     * Get a handle to a directory in the given path
     */
    public static SMBFile openDirectory(
            TreeConnect treeConnect, String path,
            EnumSet<AccessMask> accessMask,
            EnumSet<SMB2ShareAccess> shareAccess,
            SMB2CreateDisposition createDisposition)
            throws TransportException, SMBApiException {
        logger.info("OpenDirectory {},{},{},{},{}", path, accessMask, shareAccess, createDisposition);

        return open(treeConnect, path, toLong(accessMask), EnumSet.of(FileAttributes.FILE_ATTRIBUTE_DIRECTORY),
                shareAccess, createDisposition, EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE));
    }

    /**
     * Get a handle to a file
     */
    public static SMBFile openFile(
            TreeConnect treeConnect, String path, EnumSet<AccessMask> accessMask,
            SMB2CreateDisposition createDisposition)
            throws TransportException, SMBApiException {
        logger.info("OpenFile {},{},{}", path, accessMask, createDisposition);

        return open(treeConnect, path, toLong(accessMask), null, EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ),
                createDisposition, EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE));
    }


    /**
     * File in the given path exists or not
     */
    public static boolean fileExists(TreeConnect treeConnect, String path)
            throws SMBApiException, TransportException {
        return exists(treeConnect, path, EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE));
    }

    /**
     * Folder in the given path exists or not.
     */
    public static boolean folderExists(TreeConnect treeConnect, String path)
            throws SMBApiException, TransportException {
        return exists(treeConnect, path, EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE));
    }

    /**
     * Create a directory in the given path.
     */
    public static void mkdir(TreeConnect treeConnect, String path)
            throws TransportException, SMBApiException {
        logger.info("mkdir {}", path);

        SMBFile fileHandle = openDirectory(treeConnect, path,
                EnumSet.of(AccessMask.FILE_LIST_DIRECTORY, AccessMask.FILE_ADD_SUBDIRECTORY),
                EnumSet.of(SMB2ShareAccess.FILE_SHARE_DELETE, SMB2ShareAccess.FILE_SHARE_WRITE, SMB2ShareAccess
                        .FILE_SHARE_READ),
                SMB2CreateDisposition.FILE_CREATE);

        fileHandle.close();

    }

    /**
     * Get information about the given path.
     **/
    public static FileInfo getFileInformation(
            TreeConnect treeConnect, String path)
            throws SMBApiException, TransportException {

        byte[] outputBuffer = queryInfoCommon(treeConnect, path,
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
     * Remove the directory at the given path.
     */
    public static void rmdir(TreeConnect treeConnect, String path, boolean recursive)
            throws TransportException, SMBApiException {
        logger.info("rmdir {},{}", path, recursive);

        //TODO Even with DELETE_CHILD permission, receiving error, so doing the recursive way for now.
        //if (recursive) accessMask.add(SMB2DirectoryAccessMask.FILE_DELETE_CHILD);
        if (recursive) {
            List<FileInfo> list = list(treeConnect, path);
            for (FileInfo fi : list) {
                if (!EnumWithValue.EnumUtils.isSet(fi.getFileAttributes(), FileAttributes.FILE_ATTRIBUTE_DIRECTORY)) {
                    rm(treeConnect, makePath(path, fi.getFileName()));
                } else {
                    rmdir(treeConnect, makePath(path, fi.getFileName()), recursive);
                }
            }
            rmdir(treeConnect, path, false);
        } else {

            SMB2CreateRequest smb2CreateRequest =
                    openFileRequest(treeConnect, path,
                            AccessMask.DELETE.getValue(),
                            EnumSet.of(SMB2ShareAccess.FILE_SHARE_DELETE, SMB2ShareAccess.FILE_SHARE_WRITE,
                                    SMB2ShareAccess.FILE_SHARE_READ),
                            EnumSet.of(FileAttributes.FILE_ATTRIBUTE_DIRECTORY),
                            SMB2CreateDisposition.FILE_OPEN,
                            null);

            deleteCommon(treeConnect, path, smb2CreateRequest);
        }
    }

    /**
     * Remove the file at the given path
     */
    public static void rm(TreeConnect treeConnect, String path)
            throws TransportException, SMBApiException {
        logger.info("rm {}", path);
        SMB2CreateRequest smb2CreateRequest =
                openFileRequest(treeConnect, path, AccessMask.DELETE.getValue(), null, null,
                        SMB2CreateDisposition.FILE_OPEN, EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE));

        deleteCommon(treeConnect, path, smb2CreateRequest);
    }

    /**
     * Write the given input stream to the given path
     */
    public static void write(TreeConnect treeConnect, String path, boolean overWrite, InputStream srcStream)
            throws SMBApiException, IOException {
        logger.info("Write {},{}", path, overWrite);
        SMB2CreateDisposition createDisposition = SMB2CreateDisposition.FILE_OVERWRITE_IF;
        if (!overWrite) createDisposition = SMB2CreateDisposition.FILE_CREATE;
        SMBFile fileHandle =
                openFile(treeConnect, path, EnumSet.of(AccessMask.GENERIC_WRITE), createDisposition);

        try {
            fileHandle.write(srcStream);
        } finally {
            fileHandle.close();
        }
    }

    /**
     * Read the file at the given path and write the data to the given output stream
     */
    public static void read(TreeConnect treeConnect, String path, OutputStream destStream)
            throws SMBApiException, IOException {
        logger.info("Read {}", path);
        SMBFile fileHandle = openFile(treeConnect, path,
                EnumSet.of(AccessMask.GENERIC_READ), SMB2CreateDisposition.FILE_OPEN);

        try {
            fileHandle.read(destStream);
        } finally {
            fileHandle.close();
        }
    }

    /**
     * SMB2 CHANGE NOTIFY
     * <p>
     * This is implemented as blocking call which will wait until any changes have been observed.
     * Clients who expect to be continuously notified should invoke this function again to listen
     * for more changes.
     */
    public static List<SMB2ChangeNotifyResponse.FileNotifyInfo> notify(
            TreeConnect treeConnect, SMBFile
            fileHandle)
            throws TransportException, SMBApiException {

        int bufferLength = 64 * 1024;

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        SMB2ChangeNotifyRequest cnr = new SMB2ChangeNotifyRequest(
                connection.getNegotiatedDialect(),
                session.getSessionId(), treeConnect.getTreeId(),
                fileHandle.getFileId(),
                EnumSet.of(
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME,
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_DIR_NAME,
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_ATTRIBUTES,
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_CREATION,
//                                SMB2CompletionFilter.FILE_NOTIFY_CHANGE_SIZE,
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_SECURITY,
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_STREAM_SIZE,
                        SMB2CompletionFilter.FILE_NOTIFY_CHANGE_STREAM_WRITE),
                bufferLength, true);
        Future<SMB2ChangeNotifyResponse> changeNotifyResponseFuture = connection.send(cnr);

        SMB2ChangeNotifyResponse cnresponse = Futures.get(changeNotifyResponseFuture, TransportException.Wrapper);

        if (cnresponse.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(cnresponse.getHeader().getStatus(), "Notify failed for " + fileHandle);
        }

        return cnresponse.getFileNotifyInfoList();
    }

    /**
     * The SecurityDescriptor(MS-DTYP 2.4.6 SECURITY_DESCRIPTOR) for the Given Path
     */
    public static SecurityDescriptor getSecurityInfo(
            TreeConnect treeConnect, String path, EnumSet<SecurityInformation> securityInfo)
            throws SMBApiException, TransportException {

        byte[] outputBuffer = queryInfoCommon(treeConnect, path,
                SMB2QueryInfoRequest.SMB2QueryInfoType.SMB2_0_INFO_SECURITY, securityInfo, null);
        SecurityDescriptor sd = new SecurityDescriptor();
        try {
            sd.read(new SMBBuffer(outputBuffer));
        } catch (Buffer.BufferException e) {
            throw new TransportException(e);
        }
        return sd;
    }

    private static byte[] queryInfoCommon(
            TreeConnect treeConnect, String path,
            SMB2QueryInfoRequest.SMB2QueryInfoType infoType,
            EnumSet<SecurityInformation> securityInfo,
            FileInformationClass fileInformationClass)
            throws SMBApiException, TransportException {

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        SMBFile fileHandle = null;
        try {
            fileHandle = open(
                    treeConnect, path,
                    EnumWithValue.EnumUtils.toLong(EnumSet.of(AccessMask.GENERIC_READ)),
                    EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                    EnumSet.of(SMB2ShareAccess.FILE_SHARE_DELETE, SMB2ShareAccess.FILE_SHARE_WRITE,
                            SMB2ShareAccess.FILE_SHARE_READ),
                    SMB2CreateDisposition.FILE_OPEN,
                    null);
            return queryInfoCommon(fileHandle, infoType, securityInfo, fileInformationClass);
        } finally {
            if (fileHandle != null) fileHandle.closeSilently();
        }
    }

    private static byte[] queryInfoCommon(
            SMBFile fileHandle,
            SMB2QueryInfoRequest.SMB2QueryInfoType infoType,
            EnumSet<SecurityInformation> securityInfo,
            FileInformationClass fileInformationClass)
            throws SMBApiException, TransportException {

        TreeConnect treeConnect = fileHandle.getTreeConnect();
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        SMB2QueryInfoRequest qreq = new SMB2QueryInfoRequest(
                connection.getNegotiatedDialect(), session.getSessionId(), treeConnect.getTreeId(),
                fileHandle.getFileId(), infoType,
                fileInformationClass, null, null, securityInfo);
        Future<SMB2QueryInfoResponse> qiResponseFuture = connection.send(qreq);
        SMB2QueryInfoResponse qresp = Futures.get(qiResponseFuture, TransportException.Wrapper);

        if (qresp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(qresp.getHeader().getStatus(), "QUERY_INFO failed for " + fileHandle);
        }
        return qresp.getOutputBuffer();
    }

    private static boolean exists(TreeConnect treeConnect, String path, EnumSet<SMB2CreateOptions> createOptions)
            throws TransportException, SMBApiException {
        logger.info("exists {}", path);

        SMBFile fileHandle = null;
        try {
            fileHandle = open(treeConnect, path,
                    toLong(EnumSet.of(AccessMask.FILE_READ_ATTRIBUTES)),
                    EnumSet.of(FileAttributes.FILE_ATTRIBUTE_DIRECTORY),
                    EnumSet.of(SMB2ShareAccess.FILE_SHARE_DELETE, SMB2ShareAccess.FILE_SHARE_WRITE,
                            SMB2ShareAccess.FILE_SHARE_READ),
                    SMB2CreateDisposition.FILE_OPEN, createOptions);
            return true;
        } catch (SMBApiException sae) {
            if (sae.getStatus() == NtStatus.STATUS_OBJECT_NAME_NOT_FOUND) {
                return false;
            } else {
                throw sae;
            }
        } finally {
            if (fileHandle != null) fileHandle.closeSilently();
        }
    }

    private static void deleteCommon(TreeConnect treeConnect, String path, SMB2CreateRequest smb2CreateRequest)
            throws TransportException, SMBApiException {

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        // TODO Use Compounding
        Future<SMB2CreateResponse> sendFuture = connection.send(smb2CreateRequest);
        SMB2CreateResponse response = Futures.get(sendFuture, TransportException.Wrapper);

        if (response.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(response.getHeader().getStatus(), "Create failed for " + path);
        }

        SMB2FileId fileId = response.getFileId();
        try {
            byte[] dispoInfo = FileInformationFactory.getFileDispositionInfo(true);
            SMB2SetInfoRequest si_req = new SMB2SetInfoRequest(
                    connection.getNegotiatedDialect(), session.getSessionId(), treeConnect.getTreeId(),
                    SMB2SetInfoRequest.SMB2InfoType.SMB2_0_INFO_FILE, fileId,
                    FileInformationClass.FileDispositionInformation, null, dispoInfo);

            Future<SMB2SetInfoResponse> setInfoFuture = connection.send(si_req);
            SMB2SetInfoResponse setInfoResponse = Futures.get(setInfoFuture, TransportException.Wrapper);

            if (setInfoResponse.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                throw new SMBApiException(response.getHeader().getStatus(), "SetInfo failed for " + path);
            }
        } finally {
            SMB2Close closeReq = new SMB2Close(connection.getNegotiatedDialect(),
                    session.getSessionId(), treeConnect.getTreeId(), fileId);
            Future<SMB2Close> closeFuture = connection.send(closeReq);
            SMB2Close closeResponse = Futures.get(closeFuture, TransportException.Wrapper);

            if (closeResponse.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                throw new SMBApiException(response.getHeader().getStatus(), "Close failed for " + path);
            }

        }
    }

    private static SMBFile open(
            TreeConnect treeConnect, String path, long accessMask,
            EnumSet<FileAttributes> fileAttributes, EnumSet<SMB2ShareAccess> shareAccess,
            SMB2CreateDisposition createDisposition, EnumSet<SMB2CreateOptions> createOptions)
            throws TransportException, SMBApiException {
        logger.info("open {},{}", path);

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();
        SMB2CreateRequest cr = openFileRequest(
                treeConnect, path, accessMask, shareAccess, fileAttributes, createDisposition, createOptions);
        Future<SMB2CreateResponse> responseFuture = connection.send(cr);
        SMB2CreateResponse cresponse = Futures.get(responseFuture, TransportException.Wrapper);

        if (cresponse.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(cresponse.getHeader().getStatus(), "Create failed for " + path);
        }

        return new SMBFile(
                cresponse.getFileId(), treeConnect, path, null, shareAccess,
                createOptions, fileAttributes, createDisposition);
    }

    private static SMB2CreateRequest openFileRequest(
            TreeConnect treeConnect, String path,
            long accessMask,
            EnumSet<SMB2ShareAccess> shareAccess,
            EnumSet<FileAttributes> fileAttributes,
            SMB2CreateDisposition createDisposition,
            EnumSet<SMB2CreateOptions> createOptions) {

        Session session = treeConnect.getSession();
        SMB2CreateRequest cr = new SMB2CreateRequest(
                session.getConnection().getNegotiatedDialect(),
                session.getSessionId(), treeConnect.getTreeId(),
                accessMask,
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions, path);
        return cr;
    }

    private static String makePath(String first, String... more) {
        StringBuilder sb = new StringBuilder(first);
        for (int i = 0; i < more.length; i++) {
            sb.append('\\');
            sb.append(more[i]);
        }
        return sb.toString();
    }

    public SMB2FileId getFileId() {
        return fileId;
    }

    public TreeConnect getTreeConnect() {
        return treeConnect;
    }

    public List<FileInfo> list() throws TransportException, SMBApiException {
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        // Query Directory Request
        SMB2QueryDirectoryRequest qdr = new SMB2QueryDirectoryRequest(connection.getNegotiatedDialect(),
                session.getSessionId(), treeConnect.getTreeId(),
                getFileId(), FileInformationClass.FileIdBothDirectoryInformation, // FileInformationClass
                // .FileDirectoryInformation,
                EnumSet.of(SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags.SMB2_REOPEN),
                0, null);
        Future<SMB2QueryDirectoryResponse> qdFuture = connection.send(qdr);

        SMB2QueryDirectoryResponse qdResp = Futures.get(qdFuture, TransportException.Wrapper);

        if (qdResp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(qdResp.getHeader().getStatus(),
                    "Query directory failed for " + fileName + "/" + fileId);
        }
        byte[] outputBuffer = qdResp.getOutputBuffer();

        try {
            return FileInformationFactory.parseFileInformationList(
                    outputBuffer, FileInformationClass.FileIdBothDirectoryInformation);
        } catch (Buffer.BufferException e) {
            throw new TransportException(e);
        }
    }

    public void closeSilently() {
        try {
            close();
        } catch (Exception e) {
            logger.warn("File close failed for {},{},{}", fileName, treeConnect, fileId, e);
        }
    }

    public void close() throws TransportException, SMBApiException {
        Connection connection = treeConnect.getSession().getConnection();
        SMB2Close closeReq = new SMB2Close(
                connection.getNegotiatedDialect(),
                treeConnect.getSession().getSessionId(), treeConnect.getTreeId(), fileId);
        Future<SMB2Close> closeFuture = connection.send(closeReq);
        SMB2Close closeResp = Futures.get(closeFuture, TransportException.Wrapper);

        if (closeResp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(closeResp.getHeader().getStatus(), "Close failed for " + fileId);
        }
    }

    @Override
    public String toString() {
        return "SMBFile{" +
                "fileId=" + fileId +
                ", fileName='" + fileName + '\'' +
                '}';
    }

    public void write(InputStream srcStream) throws IOException, SMBApiException {
        byte[] buf = new byte[8192];
        int numRead = -1;
        int offset = 0;

        Session session = getTreeConnect().getSession();
        Connection connection = session.getConnection();


        while ((numRead = srcStream.read(buf)) != -1) {
            //logger.debug("Writing {} bytes", numRead);
            SMB2WriteRequest wreq = new SMB2WriteRequest(connection.getNegotiatedDialect(), getFileId(),
                    session.getSessionId(), getTreeConnect().getTreeId(),
                    buf, numRead, offset, 0);
            Future<SMB2WriteResponse> writeFuture = connection.send(wreq);
            SMB2WriteResponse wresp = Futures.get(writeFuture, TransportException.Wrapper);

            if (wresp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                throw new SMBApiException(wresp.getHeader().getStatus(), "Write failed for " + this);
            }
            offset += numRead;
        }
    }

    public void read(OutputStream destStream) throws IOException,
            SMBApiException {
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        long offset = 0;
        SMB2ReadRequest rreq = new SMB2ReadRequest(connection.getNegotiatedDialect(), getFileId(),
                session.getSessionId(), treeConnect.getTreeId(), offset);

        Future<SMB2ReadResponse> readResponseFuture = connection.send(rreq);
        SMB2ReadResponse rresp = Futures.get(readResponseFuture, TransportException.Wrapper);

        while (rresp.getHeader().getStatus() == NtStatus.STATUS_SUCCESS &&
                rresp.getHeader().getStatus() != NtStatus.STATUS_END_OF_FILE) {
            destStream.write(rresp.getData());
            offset += rresp.getDataLength();
            rreq = new SMB2ReadRequest(connection.getNegotiatedDialect(), getFileId(),
                    session.getSessionId(), treeConnect.getTreeId(), offset);
            readResponseFuture = connection.send(rreq);
            rresp = Futures.get(readResponseFuture, TransportException.Wrapper);
        }

        if (rresp.getHeader().getStatus() != NtStatus.STATUS_END_OF_FILE) {
            throw new SMBApiException(rresp.getHeader().getStatus(), "Read failed for " + this);
        }
    }

    // TODO CHeck it is supposed to delete on close, but should we close the handle in this method?
    public void rm()
            throws TransportException, SMBApiException {
        byte[] dispoInfo = FileInformationFactory.getFileDispositionInfo(true);
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        SMB2SetInfoRequest si_req = new SMB2SetInfoRequest(
                connection.getNegotiatedDialect(), session.getSessionId(), treeConnect.getTreeId(),
                SMB2SetInfoRequest.SMB2InfoType.SMB2_0_INFO_FILE, getFileId(), FileInformationClass
                .FileDispositionInformation,
                null, dispoInfo);
        Future<SMB2SetInfoResponse> setInfoResponseFuture = connection.send(si_req);

        SMB2SetInfoResponse receive = Futures.get(setInfoResponseFuture, TransportException.Wrapper);

        if (receive.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(receive.getHeader().getStatus(), "Tree connect request failed for " + this);
        }
    }

    public SecurityDescriptor getSecurityInfo(EnumSet<SecurityInformation> securityInfo)
            throws SMBApiException, TransportException {
        byte[] outputBuffer = queryInfoCommon(this, SMB2QueryInfoRequest.SMB2QueryInfoType.SMB2_0_INFO_SECURITY,
                securityInfo,
                null);
        SecurityDescriptor sd = new SecurityDescriptor();
        try {
            sd.read(new SMBBuffer(outputBuffer));
        } catch (Buffer.BufferException e) {
            throw new TransportException(e);
        }
        return sd;
    }

    public FileInfo getFileInformation() throws SMBApiException, TransportException {
        byte[] outputBuffer = queryInfoCommon(this, SMB2QueryInfoRequest.SMB2QueryInfoType.SMB2_0_INFO_FILE, null,
                FileInformationClass.FileAllInformation);
        try {
            return FileInformationFactory.parseFileAllInformation(
                    new Buffer.PlainBuffer(outputBuffer, Endian.LE));
        } catch (Buffer.BufferException e) {
            throw new TransportException(e);
        }
    }
}
