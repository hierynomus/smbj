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
import com.hierynomus.protocol.commons.concurrent.SingleThreadExecutorTaskQueue;
import com.hierynomus.protocol.commons.concurrent.TaskQueue;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.event.AsyncCreateRequestNotification;
import com.hierynomus.smbj.event.AsyncCreateResponseNotification;
import com.hierynomus.smbj.event.AsyncRequestMessageIdNotification;
import com.hierynomus.smbj.event.OplockBreakNotification;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.event.handler.MessageIdCallback;
import com.hierynomus.smbj.event.handler.NotificationHandler;
import com.hierynomus.smbj.paths.PathResolveException;
import com.hierynomus.smbj.paths.PathResolver;
import com.hierynomus.smbj.session.Session;

import net.engio.mbassy.listener.Handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;

import static com.hierynomus.msdtyp.AccessMask.*;
import static com.hierynomus.mserref.NtStatus.*;
import static com.hierynomus.msfscc.FileAttributes.FILE_ATTRIBUTE_DIRECTORY;
import static com.hierynomus.msfscc.FileAttributes.FILE_ATTRIBUTE_NORMAL;
import static com.hierynomus.mssmb2.SMB2CreateDisposition.FILE_CREATE;
import static com.hierynomus.mssmb2.SMB2CreateDisposition.FILE_OPEN;
import static com.hierynomus.mssmb2.SMB2CreateOptions.FILE_DIRECTORY_FILE;
import static com.hierynomus.mssmb2.SMB2CreateOptions.FILE_NON_DIRECTORY_FILE;
import static com.hierynomus.mssmb2.SMB2MessageCommandCode.SMB2_CREATE;
import static com.hierynomus.mssmb2.SMB2ShareAccess.*;
import static com.hierynomus.mssmb2.messages.SMB2QueryInfoRequest.SMB2QueryInfoType.SMB2_0_INFO_SECURITY;
import static java.util.EnumSet.of;
import static java.util.EnumSet.noneOf;

public class DiskShare extends Share {
    public static final EnumSet<SMB2MessageCommandCode> asyncSupport = of(SMB2_CREATE);
    private static final Logger logger = LoggerFactory.getLogger(DiskShare.class);
    private final PathResolver resolver;
    private NotificationHandler notificationHandler = null;

    private final boolean isCreatedTaskQueue;
    private final TaskQueue taskQueue;
    private final Set<SMB2FileId> openedOplockFileId = Collections.newSetFromMap(new ConcurrentHashMap<SMB2FileId, Boolean>());
    // Only add the messageId to Set when the operation is on the asyncSupport Set. Must remove when receive the corresponding AsyncResponse.
    private final Set<Long> asyncOperationMessageId = Collections.newSetFromMap(new ConcurrentHashMap<Long, Boolean>());

    public DiskShare(SmbPath smbPath, TreeConnect treeConnect, PathResolver pathResolver, SMBEventBus connectionPrivateBus) {
        super(smbPath, treeConnect);
        this.resolver = pathResolver;
        if (connectionPrivateBus != null) {
            connectionPrivateBus.subscribe(this);
        }
        TaskQueue taskQueueFromConfig = treeConnect.getConnection().getConfig().getTaskQueue();
        if (taskQueueFromConfig != null) {
            taskQueue = taskQueueFromConfig;
            isCreatedTaskQueue = false;
        } else {
            taskQueue = new SingleThreadExecutorTaskQueue();
            isCreatedTaskQueue = true;
        }
    }

    @Override
    public void close() throws IOException {
        super.close();
        if (isCreatedTaskQueue) {
            // cleanup for executor
            ((SingleThreadExecutorTaskQueue)taskQueue).close();
        }
        // cleanup for set
        openedOplockFileId.clear();
        asyncOperationMessageId.clear();
    }

    public DiskEntry open(String path, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        return open(path, null, null, accessMask, attributes, shareAccesses, createDisposition, createOptions);
    }

    public DiskEntry open(String path, SMB2OplockLevel oplockLevel, SMB2ImpersonationLevel impersonationLevel, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        SMB2CreateResponseDiskEntry result = openWithResponse(path, oplockLevel, impersonationLevel, accessMask, attributes, shareAccesses, createDisposition, createOptions);
        return result.getDiskEntry();
    }

    /***
     * Synchronously open a diskEntry. Returning the diskEntry with the createResponse.
     *
     * @param path target file path
     * @param oplockLevel requesting oplock level
     * @param impersonationLevel requesting impersonation level
     * @param accessMask desired access
     * @param attributes file attributes
     * @param shareAccesses the share access of this create request
     * @param createDisposition create disposition of this create request
     * @param createOptions create options of this create request
     * @return the diskEntry and the corresponding createResponse.
     */
    public SMB2CreateResponseDiskEntry openWithResponse(String path, SMB2OplockLevel oplockLevel, SMB2ImpersonationLevel impersonationLevel, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        SmbPath pathAndFile = new SmbPath(smbPath, path);
        SMB2CreateResponseContext response = createFileAndResolve(pathAndFile, oplockLevel, impersonationLevel, accessMask, attributes, shareAccesses, createDisposition, createOptions);
        return new SMB2CreateResponseDiskEntry(response.resp, getDiskEntry(path, response));
    }

    /***
     * Send a create request and return a Future for create response. User are required to deal with DFS issue by himself.
     *
     * @param path target file path
     * @param oplockLevel requesting oplock level
     * @param impersonationLevel requesting impersonation level
     * @param accessMask desired access
     * @param attributes file attributes
     * @param shareAccesses the share access of this create request
     * @param createDisposition create disposition of this create request
     * @param createOptions create options of this create request
     * @return a Future to be used to retrieve the create response packet
     */
    public Future<SMB2CreateResponse> openAsync(String path, SMB2OplockLevel oplockLevel, SMB2ImpersonationLevel impersonationLevel, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        return openAsync(path, oplockLevel, impersonationLevel, accessMask, attributes, shareAccesses, createDisposition, createOptions, null);
    }

    /***
     * Send a create request and callback for messageId for create response. User are required to deal with DFS issue by himself.
     *
     * @param path target file path
     * @param oplockLevel requesting oplock level
     * @param impersonationLevel requesting impersonation level
     * @param accessMask desired access
     * @param attributes file attributes
     * @param shareAccesses the share access of this create request
     * @param createDisposition create disposition of this create request
     * @param createOptions create options of this create request
     * @param messageIdCallback callback to return corresponding messageId
     * @return a Future to be used to retrieve the create response packet
     */
    public Future<SMB2CreateResponse> openAsync(String path, SMB2OplockLevel oplockLevel, SMB2ImpersonationLevel impersonationLevel, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions, MessageIdCallback messageIdCallback) {
        SmbPath pathAndFile = new SmbPath(smbPath, path);
        return super.createAsync(pathAndFile, oplockLevel, impersonationLevel, accessMask, attributes, shareAccesses, createDisposition, createOptions, messageIdCallback);
    }

    @Override
    protected Set<NtStatus> getCreateSuccessStatus() {
        return resolver.handledStates();
    }

    private SMB2CreateResponseContext createFileAndResolve(SmbPath path, SMB2OplockLevel oplockLevel, SMB2ImpersonationLevel impersonationLevel, Set<AccessMask> accessMask, Set<FileAttributes> fileAttributes, Set<SMB2ShareAccess> shareAccess, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        SMB2CreateResponse resp = super.createFile(path, oplockLevel, impersonationLevel, accessMask, fileAttributes, shareAccess, createDisposition, createOptions);
        try {
            SmbPath target = resolver.resolve(session, resp, path);
            DiskShare resolveShare = this;
            Session connectedSession = this.session;
            if (!path.isOnSameHost(target)) {
                connectedSession = buildNewSession(resp, target);
            }
            if (!path.isOnSameShare(target)) {
                resolveShare = (DiskShare) connectedSession.connectShare(target.getShareName());
            }
            if (!path.equals(target)) {
                return resolveShare.createFileAndResolve(target, oplockLevel, impersonationLevel, accessMask, fileAttributes, shareAccess, createDisposition, createOptions);
            }
        } catch (PathResolveException e) {
            throw new SMBApiException(e.getStatus(), SMB2MessageCommandCode.SMB2_CREATE, "Cannot resolve path " + path, e);
        }
        return new SMB2CreateResponseContext(resp, this);
    }

    private Session buildNewSession(SMB2CreateResponse resp, SmbPath target) {
        SMBClient client = treeConnect.getConnection().getClient();
        try {
            return session.buildNestedSession(target);
        } catch (SMBRuntimeException e) {
            throw new SMBApiException(resp.getHeader(), "Cannot connect to resolved path " + target, e);
        }
    }

    public DiskEntry getDiskEntry(String path, SMB2CreateResponseContext responseContext) {
        SMB2CreateResponse response = responseContext.resp;
        DiskEntry diskEntry;
        if (response.getFileAttributes().contains(FILE_ATTRIBUTE_DIRECTORY)) {
            diskEntry = new Directory(response.getFileId(), responseContext.share, path);
        } else {
            diskEntry = new File(response.getFileId(), responseContext.share, path);
        }
        // if oplock level is not none, put it to set.
        if (response.getOplockLevel() != SMB2OplockLevel.SMB2_OPLOCK_LEVEL_NONE) {
            openedOplockFileId.add(diskEntry.fileId);
        }
        return diskEntry;
    }

    /**
     * Get a handle to a directory in the given path
     */
    public Directory openDirectory(String path, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        return openDirectory(path, null, null, accessMask, attributes, shareAccesses, createDisposition, createOptions);
    }

    /**
     * Get a handle to a directory in the given path
     */
    public Directory openDirectory(String path, SMB2OplockLevel oplockLevel, SMB2ImpersonationLevel impersonationLevel, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        EnumSet<SMB2CreateOptions> actualCreateOptions = createOptions != null ? EnumSet.copyOf(createOptions) : EnumSet.noneOf(SMB2CreateOptions.class);
        actualCreateOptions.add(FILE_DIRECTORY_FILE);
        actualCreateOptions.remove(FILE_NON_DIRECTORY_FILE);

        EnumSet<FileAttributes> actualAttributes = attributes != null ? EnumSet.copyOf(attributes) : EnumSet.noneOf(FileAttributes.class);
        actualAttributes.add(FILE_ATTRIBUTE_DIRECTORY);

        return (Directory) open(
            path,
            oplockLevel,
            impersonationLevel,
            accessMask,
            actualAttributes,
            shareAccesses,
            createDisposition,
            actualCreateOptions
        );
    }

    /**
     * Get a handle to a file in the given path
     */
    public File openFile(String path, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        return openFile(path, null, null, accessMask, attributes, shareAccesses, createDisposition, createOptions);
    }

    /**
     * Get a handle to a file in the given path
     */
    public File openFile(String path, SMB2OplockLevel oplockLevel, SMB2ImpersonationLevel impersonationLevel, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        EnumSet<SMB2CreateOptions> actualCreateOptions = createOptions != null ? EnumSet.copyOf(createOptions) : EnumSet.noneOf(SMB2CreateOptions.class);
        actualCreateOptions.add(FILE_NON_DIRECTORY_FILE);
        actualCreateOptions.remove(FILE_DIRECTORY_FILE);

        EnumSet<FileAttributes> actualAttributes = attributes != null ? EnumSet.copyOf(attributes) : EnumSet.noneOf(FileAttributes.class);
        actualAttributes.remove(FILE_ATTRIBUTE_DIRECTORY);

        return (File) open(
            path,
            oplockLevel,
            impersonationLevel,
            accessMask,
            actualAttributes,
            shareAccesses,
            createDisposition,
            actualCreateOptions
        );
    }

    @Override
    void closeFileId(SMB2FileId fileId) throws SMBApiException {
        super.closeFileId(fileId);
        // remove the the fileId from set when success, i.e. no Exception throws
        openedOplockFileId.remove(fileId);
    }

    /**
     * File in the given path exists or not
     */
    public boolean fileExists(String path) throws SMBApiException {
        return exists(path, of(FILE_NON_DIRECTORY_FILE), of(STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_FILE_IS_A_DIRECTORY));
    }

    /**
     * Folder in the given path exists or not.
     */
    public boolean folderExists(String path) throws SMBApiException {
        return exists(path, of(FILE_DIRECTORY_FILE), of(STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_NOT_A_DIRECTORY));
    }

    private boolean exists(String path, EnumSet<SMB2CreateOptions> createOptions, Set<NtStatus> acceptedStatuses) throws SMBApiException {
        try (DiskEntry ignored = open(path, of(FILE_READ_ATTRIBUTES), of(FILE_ATTRIBUTE_NORMAL), ALL, FILE_OPEN, createOptions)) {
            return true;
        } catch (SMBApiException sae) {
            if (acceptedStatuses.contains(sae.getStatus())) {
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
        try (Directory d = openDirectory(path, of(FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_EA), null, ALL, FILE_OPEN, null)) {
            return d.list(informationClass, searchPattern);
        }
    }

    /**
     * Create a directory in the given path.
     */
    public void mkdir(String path) throws SMBApiException {
        Directory fileHandle = openDirectory(
            path,
            of(FILE_LIST_DIRECTORY, FILE_ADD_SUBDIRECTORY),
            of(FILE_ATTRIBUTE_DIRECTORY),
            ALL,
            FILE_CREATE,
            of(FILE_DIRECTORY_FILE));
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
        try (DiskEntry e = open(path, of(FILE_READ_ATTRIBUTES, FILE_READ_EA), null, ALL, FILE_OPEN, null)) {
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
        try (DiskEntry e = open(path, of(FILE_WRITE_ATTRIBUTES, FILE_WRITE_EA), null, ALL, FILE_OPEN, null)) {
            e.setFileInformation(information);
        }
    }

    /**
     * Get Share Information for the current Disk Share
     *
     * @return the ShareInfo
     */
    public ShareInfo getShareInformation() throws SMBApiException {
        try (Directory directory = openDirectory("", of(FILE_READ_ATTRIBUTES), null, ALL, FILE_OPEN, null)) {
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
                of(DELETE),
                of(FILE_ATTRIBUTE_DIRECTORY),
                of(FILE_SHARE_DELETE, FILE_SHARE_WRITE, FILE_SHARE_READ),
                FILE_OPEN,
                of(FILE_DIRECTORY_FILE)
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
            of(DELETE),
            of(FILE_ATTRIBUTE_NORMAL),
            of(FILE_SHARE_DELETE, FILE_SHARE_WRITE, FILE_SHARE_READ),
            FILE_OPEN,
            of(FILE_NON_DIRECTORY_FILE)
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
        EnumSet<AccessMask> accessMask = of(READ_CONTROL);
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
        Set<AccessMask> accessMask = noneOf(AccessMask.class);
        if (securityInfo.contains(SecurityInformation.SACL_SECURITY_INFORMATION)) {
            accessMask.add(ACCESS_SYSTEM_SECURITY);
        }
        if (securityInfo.contains(SecurityInformation.OWNER_SECURITY_INFORMATION) || securityInfo.contains(SecurityInformation. GROUP_SECURITY_INFORMATION)) {
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

    /***
     * 3.2.5.19 Receiving an SMB2 OPLOCK_BREAK Notification, this handler is responsible to call acknowledgeOplockBreak if needed. Set the handler for Receiving an Oplock Break Notification.
     * You MUST set this handler before create/open diskEntry with oplock.
     *
     * @param handler handler for Receiving an Oplock Break Notification and Async Create Request/Response.
     */
    public void setNotificationHandler(NotificationHandler handler) {
        this.notificationHandler = handler;
    }

    /***
     * Record the messageId for the Async Operation.
     *
     * @param asyncRequestMessageIdNotification messageId requires handle Async Response for specific sessionId and treeId.
     */
    @Handler
    @SuppressWarnings("unused")
    private void setMessageIdForSupportedAsyncOperation(final AsyncRequestMessageIdNotification asyncRequestMessageIdNotification) {
        try {
            if (asyncRequestMessageIdNotification.getSessionId() == this.sessionId
                && asyncRequestMessageIdNotification.getTreeId() == this.treeId) {
                // add the messageId to Set if Async Request is sending by this DiskShare
                asyncOperationMessageId.add(asyncRequestMessageIdNotification.getMessageId());
            }
        } catch (Throwable t) {
            logger.error("Handling setMessageIdForSupportedAsyncOperation error occur : ", t);
            throw t;
        }
    }

    /***
     * Handler for handing the oplock break notification event from server. 3.2.5.19 Receiving an SMB2 OPLOCK_BREAK Notification.
     *
     * @param oplockBreakNotification received oplock break notification from server.
     */
    @Handler
    @SuppressWarnings("unused")
    private void oplockBreakNotification(final OplockBreakNotification oplockBreakNotification) {
        try {

            final SMB2FileId fileId = oplockBreakNotification.getFileId();
            final SMB2OplockLevel oplockLevel = oplockBreakNotification.getOplockLevel();
            // Check should this DiskShare handle this oplock break notification. If not, just ignore.
            if (openedOplockFileId.contains(fileId)) {
                logger.debug("FileId {} received OplockBreakNotification, Oplock level {}", fileId,
                             oplockLevel);
                if (notificationHandler != null) {
                    // Preventing the improper use of handler (holding the thread). if holding thread, timeout exception will be throw.
                    // submit to taskQueue only when this DiskShare opened a handle with this fileId. Otherwise, ignore it.
                    taskQueue.execute(new Runnable() {
                        @Override
                        public void run() {
                            notificationHandler.handleOplockBreakNotification(oplockBreakNotification);
                        }
                    });
                } else {
                    logger.warn(
                        "FileId {}, NotificationHandler not exist to handle Oplock Break. On treeId = {}",
                        fileId, this.treeId);
                    throw new IllegalStateException(
                        "NotificationHandler not exist to handle Oplock Break.");
                }
            }
        } catch (Throwable t) {
            logger.error("Handling oplockBreakNotification error occur : ", t);
            throw t;
        }
    }

    /***
     * Async create request handler.
     *
     * @param asyncCreateRequestNotification filePath with the corresponding messageId.
     */
    @Handler
    @SuppressWarnings("unused")
    private void createRequestNotification(final AsyncCreateRequestNotification asyncCreateRequestNotification) {
        try {
            // Checking treeId can always map a DiskShare for AsyncCreateRequestNotification, because this happens before sending message.
            if (asyncCreateRequestNotification.getSessionId() == this.sessionId
                && asyncCreateRequestNotification.getTreeId() == this.treeId) {
                if (notificationHandler != null) {
                    // Preventing the improper use of handler (holding the thread). if holding thread, timeout exception will be throw.
                    // submit to taskQueue only when sessionId and treeId match. Otherwise, ignore it.
                    taskQueue.execute(new Runnable() {
                        @Override
                        public void run() {
                            notificationHandler.handleAsyncCreateRequestNotification(asyncCreateRequestNotification);
                        }
                    });
                } else {
                    logger.debug("NotificationHandler not exist to handle asyncCreateRequestNotification. On treeId = {}", this.treeId);
                }
            } else {
                logger.debug("asyncCreateRequestNotification ignored. this.treeId = {}, notification.getTreeId() = {}", this.treeId, asyncCreateRequestNotification.getTreeId());
            }
        } catch (Throwable t) {
            logger.error("Handling createRequestNotification error occur : ", t);
            throw t;
        }
    }

    /***
     * Async create response handler. This is also a oplock related handler.
     * Passing the createResponse Future to the client.
     * This is also intended to prevent oplock break too fast and not able to handle oplock break notification properly.
     * Notify the client oplock is granted on createResponse but still under processing.
     *
     * @param asyncCreateResponseNotification the corresponding messageId and fileId with the Future of createResponse.
     */
    @Handler
    @SuppressWarnings("unused")
    private void createResponseNotification(final AsyncCreateResponseNotification asyncCreateResponseNotification) {
        try {
            // No matter the notificationHandler is set or not. Always try to remove the messageId from the Set.
            boolean shouldHandle = asyncOperationMessageId.remove(asyncCreateResponseNotification.getMessageId());
            // Check should this DiskShare handle the create response. If not, just ignore.
            if (shouldHandle) {
                if (notificationHandler != null) {
                    // Preventing the improper use of handler (holding the thread). if holding thread, timeout exception will be throw.
                    // submit to taskQueue only if createRequest is sent out by this DiskShare. Otherwise, ignore it.
                    taskQueue.execute(new Runnable() {
                        @Override
                        public void run() {
                            notificationHandler.handleAsyncCreateResponseNotification(asyncCreateResponseNotification);
                        }
                    });
                } else {
                    logger.debug("NotificationHandler not exist to handle asyncCreateResponseNotification. On treeId = {}", this.treeId);
                }
            } else {
                logger.debug("asyncCreateResponseNotification ignored. MessageId = {}, is not handled by this.treeId = {}", asyncCreateResponseNotification.getMessageId(), this.treeId);
            }
        } catch (Throwable t) {
            logger.error("Handling createResponseNotification error occur : ", t);
            throw t;
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getSmbPath() + "]";
    }

    /**
     * A return object for the {@link #createFileAndResolve(SmbPath, SMB2OplockLevel, SMB2ImpersonationLevel, Set, Set, Set, SMB2CreateDisposition, Set)} call.
     *
     * This object wraps the {@link SMB2CreateResponse} and the actual {@link Share} which generated it if the path needed to be resolved.
     */
    public static class SMB2CreateResponseContext {
        final SMB2CreateResponse resp;
        final DiskShare share;

        public SMB2CreateResponseContext(SMB2CreateResponse resp, DiskShare share) {
            this.resp = resp;
            this.share = share;
        }
    }

    /**
     * A return object for the {@link #openWithResponse(String, SMB2OplockLevel, SMB2ImpersonationLevel, Set, Set, Set, SMB2CreateDisposition, Set)} call.
     *
     * This object wraps the {@link SMB2CreateResponse} and the diskEntry instance {@link DiskEntry}.
     */
    public static class SMB2CreateResponseDiskEntry {
        final SMB2CreateResponse resp;
        final DiskEntry diskEntry;

        public SMB2CreateResponseDiskEntry(SMB2CreateResponse resp, DiskEntry diskEntry) {
            this.resp = resp;
            this.diskEntry = diskEntry;
        }

        public SMB2CreateResponse getCreateResponse() {
            return resp;
        }

        public DiskEntry getDiskEntry() {
            return diskEntry;
        }
    }
}
