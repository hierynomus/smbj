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
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.FileSystemInformationClass;
import com.hierynomus.msfscc.fileinformation.*;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2CreateResponse;
import com.hierynomus.mssmb2.messages.SMB2QueryInfoRequest;
import com.hierynomus.mssmb2.messages.SMB2SetInfoRequest;
import com.hierynomus.mssmb2.messages.create.SMB2CreateContext;
import com.hierynomus.mssmb2.messages.create.SMB2LeaseCreateContext;
import com.hierynomus.mssmb2.messages.create.SMB2LeaseResponseContext;
import com.hierynomus.smbj.connection.ConnectionContext;
import com.hierynomus.smbj.connection.LeaseEntry;
import com.hierynomus.smbj.connection.LeaseManager;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.paths.PathResolveException;
import com.hierynomus.smbj.paths.PathResolver;
import com.hierynomus.smbj.session.Session;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static com.hierynomus.msdtyp.AccessMask.*;
import static com.hierynomus.mserref.NtStatus.*;
import static com.hierynomus.msfscc.FileAttributes.FILE_ATTRIBUTE_DIRECTORY;
import static com.hierynomus.msfscc.FileAttributes.FILE_ATTRIBUTE_NORMAL;
import static com.hierynomus.mssmb2.SMB2CreateDisposition.FILE_CREATE;
import static com.hierynomus.mssmb2.SMB2CreateDisposition.FILE_OPEN;
import static com.hierynomus.mssmb2.SMB2CreateOptions.FILE_DIRECTORY_FILE;
import static com.hierynomus.mssmb2.SMB2CreateOptions.FILE_NON_DIRECTORY_FILE;
import static com.hierynomus.mssmb2.SMB2ShareAccess.*;
import static com.hierynomus.mssmb2.messages.SMB2QueryInfoRequest.SMB2QueryInfoType.SMB2_0_INFO_SECURITY;
import static java.util.EnumSet.noneOf;
import static java.util.EnumSet.of;

public class DiskShare extends Share {
    private final PathResolver resolver;

    public DiskShare(SmbPath smbPath, TreeConnect treeConnect, PathResolver pathResolver) {
        super(smbPath, treeConnect);
        this.resolver = pathResolver;
    }

    public DiskEntry open(String path, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        SmbPath pathAndFile = new SmbPath(smbPath, path);
        SMB2CreateResponseContext response = resolveAndCreateFile(pathAndFile, null, accessMask, attributes, shareAccesses, createDisposition, createOptions,
            SMB2OplockLevel.SMB2_OPLOCK_LEVEL_NONE, java.util.Collections.<SMB2CreateContext>emptyList());
        return getDiskEntry(response);
    }

    ConnectionContext getConnectionContext() {
        return session.getConnection().getConnectionContext();
    }

    @Override
    protected StatusHandler getCreateStatusHandler() {
        return resolver.statusHandler();
    }

    private SMB2CreateResponseContext createFileAndResolve(final SmbPath path, final SMB2ImpersonationLevel impersonationLevel, final Set<AccessMask> accessMask, final Set<FileAttributes> fileAttributes, final Set<SMB2ShareAccess> shareAccess, final SMB2CreateDisposition createDisposition, final Set<SMB2CreateOptions> createOptions, final SMB2OplockLevel oplockLevel, final List<SMB2CreateContext> createContexts) {
        final SMB2CreateResponse resp = super.createFile(path, impersonationLevel, accessMask, fileAttributes, shareAccess, createDisposition, createOptions, oplockLevel, createContexts);
        try {
            SMB2CreateResponseContext target = resolver.resolve(session, resp, path, new PathResolver.ResolveAction<SMB2CreateResponseContext>() {
                @Override
                public SMB2CreateResponseContext apply(SmbPath target) {
                    DiskShare resolveShare = rerouteIfNeeded(path, target);
                    if (!path.equals(target)) {
                        return resolveShare.createFileAndResolve(target, impersonationLevel, accessMask, fileAttributes, shareAccess, createDisposition, createOptions, oplockLevel, createContexts);
                    } else {
                        return null;
                    }
                }
            });

            if (target != null) {
                return target;
            }

            return new SMB2CreateResponseContext(resp, path, this);
        } catch (PathResolveException e) {
            throw new SMBApiException(e.getStatusCode(), SMB2MessageCommandCode.SMB2_CREATE,
                "Cannot resolve path " + path, e);
        }
    }

    private SMB2CreateResponseContext resolveAndCreateFile(final SmbPath path,
                                                           final SMB2ImpersonationLevel impersonationLevel, final Set<AccessMask> accessMask,
                                                           final Set<FileAttributes> fileAttributes, final Set<SMB2ShareAccess> shareAccess,
                                                           final SMB2CreateDisposition createDisposition, final Set<SMB2CreateOptions> createOptions,
                                                           final SMB2OplockLevel oplockLevel, final List<SMB2CreateContext> createContexts) {
        try {
            SMB2CreateResponseContext target = resolver.resolve(session, path, new PathResolver.ResolveAction<SMB2CreateResponseContext>() {
                @Override
                public SMB2CreateResponseContext apply(SmbPath target) {
                    DiskShare resolvedShare = rerouteIfNeeded(path, target);
                    return resolvedShare.createFileAndResolve(target, impersonationLevel, accessMask, fileAttributes,
                        shareAccess, createDisposition, createOptions, oplockLevel, createContexts);
                }
            });

            return target;
        } catch (PathResolveException pre) {
            throw new SMBApiException(pre.getStatus().getValue(), SMB2MessageCommandCode.SMB2_CREATE,
                "Cannot resolve path " + path, pre);
        }
    }

    private DiskShare rerouteIfNeeded(SmbPath path, SmbPath target) {
        Session connectedSession = this.session;
        if (!path.isOnSameHost(target)) {
            connectedSession = connectedSession.getNestedSession(target);
        }
        if (!path.isOnSameShare(target)) {
            return (DiskShare) connectedSession.connectShare(target.getShareName());
        }
        return this;
    }

    protected DiskEntry getDiskEntry(SMB2CreateResponseContext responseContext) {
        SMB2CreateResponse response = responseContext.resp;
        if (response.getFileAttributes().contains(FILE_ATTRIBUTE_DIRECTORY)) {
            return new Directory(response.getFileId(), responseContext.share, responseContext.target);
        } else {
            return new File(response.getFileId(), responseContext.share, responseContext.target);
        }
    }

    /**
     * Get a handle to a directory in the given path
     */
    public Directory openDirectory(String path, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        EnumSet<SMB2CreateOptions> actualCreateOptions = createOptions != null ? EnumSet.copyOf(createOptions) : EnumSet.noneOf(SMB2CreateOptions.class);
        actualCreateOptions.add(FILE_DIRECTORY_FILE);
        actualCreateOptions.remove(FILE_NON_DIRECTORY_FILE);

        EnumSet<FileAttributes> actualAttributes = attributes != null ? EnumSet.copyOf(attributes) : EnumSet.noneOf(FileAttributes.class);
        actualAttributes.add(FILE_ATTRIBUTE_DIRECTORY);

        if (getConnectionContext().supportsDirectoryLeasing()) {
            return openDirectoryWithLease(path, accessMask, actualAttributes, shareAccesses, createDisposition, actualCreateOptions);
        }

        return (Directory) open(
            path,
            accessMask,
            actualAttributes,
            shareAccesses,
            createDisposition,
            actualCreateOptions
        );
    }

    /**
     * Open a directory requesting an SMB3 directory lease (V2 RqLs, RH). The {@link LeaseEntry}
     * is registered in the connection's {@link LeaseManager} <b>before</b> the CREATE is sent
     * (an async break can race the grant response), then folded with the granted state.
     */
    private Directory openDirectoryWithLease(String path, Set<AccessMask> accessMask, Set<FileAttributes> attributes,
                                             Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition,
                                             Set<SMB2CreateOptions> createOptions) {
        LeaseManager lm = session.getConnection().getLeaseManager();
        SmbPath full = new SmbPath(smbPath, path);
        String rel = full.getPath() == null ? "" : full.getPath();

        LeaseKey leaseKey = lm.leaseKeyForPath(rel);
        SmbPath parent = full.getParent();
        LeaseKey parentKey = parent != null ? lm.leaseKeyForExistingPath(parent.getPath() == null ? "" : parent.getPath()) : null;

        long requestedState = SMB2LeaseState.readHandle();
        SMB2CreateContext leaseCtx = SMB2LeaseCreateContext.v2(leaseKey, requestedState, parentKey).toCreateContext();

        // Reuse a live per-path lease entry so the app's open/close of its own handles never
        // orphans the cache's dedicated handle (kept on the entry). Each CREATE still returns a
        // fresh handle to the caller; the lease is shared by lease key.
        LeaseEntry existing = lm.getByPath(rel);
        boolean reuse = existing != null && !existing.isBroken();
        LeaseEntry entry = reuse ? existing : new LeaseEntry(leaseKey, parentKey, requestedState, rel);
        if (!reuse) {
            lm.register(entry); // *** register BEFORE send ***
        }

        SMB2CreateResponseContext rc;
        try {
            rc = resolveAndCreateFile(full, null, accessMask, attributes, shareAccesses, createDisposition, createOptions,
                SMB2OplockLevel.SMB2_OPLOCK_LEVEL_LEASE, java.util.Collections.singletonList(leaseCtx));
        } catch (RuntimeException e) {
            if (!reuse) {
                lm.unregister(leaseKey);
            }
            throw e;
        }

        SMB2CreateResponse resp = rc.resp;
        SMB2LeaseResponseContext lease = null;
        try {
            lease = resp.getLeaseResponseContext();
        } catch (Buffer.BufferException be) {
            throw new SMBRuntimeException("Failed to parse lease response context", be);
        }
        if (resp.getOplockLevel() == SMB2OplockLevel.SMB2_OPLOCK_LEVEL_LEASE && lease != null) {
            entry.setFileId(resp.getFileId());
            entry.setGrantedState(lease.getLeaseState());
            entry.setEpoch(lease.getEpoch());
            entry.setGranted(true);
            // Record the owning session/tree/dialect so an inbound break can be acknowledged.
            entry.setOwner(session, getTreeConnect().getTreeId(), getTreeConnect().getNegotiatedProtocol().getDialect());
        } else {
            if (!reuse) {
                lm.unregister(leaseKey); // server granted no lease
            }
            entry = null;
        }
        return new Directory(resp.getFileId(), rc.share, rc.target, entry);
    }

    /** Open (or, when reused, re-open) a dedicated leased directory handle for the cache to enumerate
     *  through. The handle is stored on the lease entry and kept open — never returned to callers. */
    private Directory openLeasedCacheHandle(String path, Set<AccessMask> accessMask) {
        Directory d = openDirectory(path,
            accessMask == null ? of(FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_EA) : accessMask,
            null, ALL, FILE_OPEN, null);
        LeaseEntry e = d.getLeaseEntry();
        if (e != null && e.isGranted() && SMB2LeaseState.isReadHandle(e.getGrantedState())) {
            e.setCacheDirectory(d);
        }
        return d;
    }

    public File openFile(String path, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        EnumSet<SMB2CreateOptions> actualCreateOptions = createOptions != null ? EnumSet.copyOf(createOptions) : EnumSet.noneOf(SMB2CreateOptions.class);
        actualCreateOptions.add(FILE_NON_DIRECTORY_FILE);
        actualCreateOptions.remove(FILE_DIRECTORY_FILE);

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

    private static final StatusHandler FILE_EXISTS_STATUS_HANDLER = new StatusHandler() {
        @Override
        public boolean isSuccess(long statusCode) {
            return statusCode == STATUS_OBJECT_NAME_NOT_FOUND.getValue()
                || statusCode == STATUS_OBJECT_PATH_NOT_FOUND.getValue()
                || statusCode == STATUS_FILE_IS_A_DIRECTORY.getValue()
                || statusCode == STATUS_DELETE_PENDING.getValue();
        }
    };

    /**
     * File in the given path exists or not
     */
    public boolean fileExists(String path) throws SMBApiException {
        return exists(path, of(FILE_NON_DIRECTORY_FILE), FILE_EXISTS_STATUS_HANDLER);
    }

    private static final StatusHandler FOLDER_EXISTS_STATUS_HANDLER = new StatusHandler() {
        @Override
        public boolean isSuccess(long statusCode) {
            return statusCode == STATUS_OBJECT_NAME_NOT_FOUND.getValue()
                || statusCode == STATUS_OBJECT_PATH_NOT_FOUND.getValue()
                || statusCode == STATUS_NOT_A_DIRECTORY.getValue()
                || statusCode == STATUS_DELETE_PENDING.getValue();
        }
    };

    /**
     * Folder in the given path exists or not.
     */
    public boolean folderExists(String path) throws SMBApiException {
        return exists(path, of(FILE_DIRECTORY_FILE), FOLDER_EXISTS_STATUS_HANDLER);
    }

    private boolean exists(String path, EnumSet<SMB2CreateOptions> createOptions, StatusHandler statusHandler) throws SMBApiException {
        try (DiskEntry ignored = open(path, of(FILE_READ_ATTRIBUTES), of(FILE_ATTRIBUTE_NORMAL), ALL, FILE_OPEN, createOptions)) {
            return true;
        } catch (SMBApiException sae) {
            if (statusHandler.isSuccess(sae.getStatusCode())) {
                return false;
            } else {
                throw sae;
            }
        }
    }

    /**
     * Equivalent to calling {@link #list(String, Class, String, EnumSet<AccessMask>) list(path, FileIdBothDirectoryInformation.class, null, null)}.
     *
     * @see #list(String, Class, String, EnumSet<AccessMask>)
     */
    public List<FileIdBothDirectoryInformation> list(String path) throws SMBApiException {
        return list(path, FileIdBothDirectoryInformation.class, null, null);
    }

    /**
     * Equivalent to calling {@link #list(String, Class, String, EnumSet<AccessMask>) list(path, FileIdBothDirectoryInformation.class, searchPattern, null)}.
     *
     * @see #list(String, Class, String, EnumSet<AccessMask>)
     */
    public List<FileIdBothDirectoryInformation> list(String path, String searchPattern) throws SMBApiException {
        return list(path, FileIdBothDirectoryInformation.class, searchPattern, null);
    }

    /**
     * Equivalent to calling {@link #list(String, Class, String, EnumSet<AccessMask>) list(path, informationClass, null, null)}.
     *
     * @see #list(String, Class, String, EnumSet<AccessMask>)
     */
    public <I extends FileDirectoryQueryableInformation> List<I> list(String path, Class<I> informationClass) {
        return list(path, informationClass, null, null);
    }

    /**
     * Opens the given path for read-only access and performs a directory listing.
     *
     * @see Directory#iterator(Class, String)
     */
    public <I extends FileDirectoryQueryableInformation> List<I> list(String path, Class<I> informationClass, String searchPattern, EnumSet<AccessMask> accessMask) {
        // Directory-lease cache fast path: when a usable RH lease is held for this directory,
        // serve a repeat listing from memory; otherwise enumerate via the kept-open leased handle
        // and populate. With leasing off / no lease / a real searchPattern this is the unchanged
        // open-enumerate-close behaviour.
        if (getConnectionContext().supportsDirectoryLeasing() && LeasedDirectoryCache.isCacheable(searchPattern)) {
            LeaseManager lm = session.getConnection().getLeaseManager();
            SmbPath full = new SmbPath(smbPath, path);
            String rel = full.getPath() == null ? "" : full.getPath();

            LeaseEntry entry = lm.getByPath(rel);
            if (entry != null && entry.isGranted() && !entry.isBroken()
                    && SMB2LeaseState.isReadHandle(entry.getGrantedState())) {
                List<I> hit = entry.getCache().serve(rel, informationClass, searchPattern);
                if (hit != null) {
                    return hit; // SERVED FROM CACHE — no CREATE / QUERY_DIRECTORY / CLOSE
                }
                // Miss: enumerate through the dedicated cache handle (owned by us, not the app).
                // If it was closed out from under us (e.g. server tore it down), re-open once.
                Directory dir = entry.getCacheDirectory();
                List<I> result;
                if (dir != null) {
                    try {
                        result = dir.list(informationClass, searchPattern);
                    } catch (SMBApiException e) {
                        if (e.getStatusCode() != STATUS_FILE_CLOSED.getValue()) {
                            throw e;
                        }
                        entry.setCacheDirectory(null);
                        result = openLeasedCacheHandle(path, accessMask).list(informationClass, searchPattern);
                    }
                } else {
                    result = openLeasedCacheHandle(path, accessMask).list(informationClass, searchPattern);
                }
                LeaseEntry cur = lm.getByPath(rel);
                if (cur != null) {
                    cur.getCache().populate(rel, informationClass, searchPattern, result);
                }
                return result;
            }

            // No live cached lease for this dir: open a dedicated leased handle (kept open), enumerate,
            // and — if a usable RH lease was granted — populate so repeats hit cache.
            Directory opened = openLeasedCacheHandle(path, accessMask);
            LeaseEntry openedEntry = opened.getLeaseEntry();
            if (openedEntry != null && openedEntry.isGranted() && SMB2LeaseState.isReadHandle(openedEntry.getGrantedState())) {
                List<I> result = opened.list(informationClass, searchPattern); // handle retained for caching
                openedEntry.getCache().populate(rel, informationClass, searchPattern, result);
                return result;
            }
            try {
                return opened.list(informationClass, searchPattern);
            } finally {
                if (opened != null) {
                    opened.closeSilently();
                }
            }
        }

        Directory d = openDirectory(path,
            accessMask == null ? of(FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_EA) : accessMask,
            null, ALL, FILE_OPEN, null);
        try {
            return d.list(informationClass, searchPattern);
        } finally {
            if (d != null) {
                d.closeSilently();
            }
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
    public FileAllInformation getFileInformation(SMB2FileId fileId) throws SMBApiException {
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
     * Get Volume Information for the current Disk Share
     *
     * @return the VolumeInfo
     */
    public VolumeInfo getVolumeInfo() throws SMBApiException {
        try (Directory directory = openDirectory("", of(FILE_READ_ATTRIBUTES), null, ALL, FILE_OPEN, null)) {
            byte[] outputBuffer = queryInfo(
                directory.getFileId(),
                SMB2QueryInfoRequest.SMB2QueryInfoType.SMB2_0_INFO_FILESYSTEM,
                null,
                null,
                FileSystemInformationClass.FileFsVolumeInformation
            ).getOutputBuffer();

            try {
                return VolumeInfo.parseFileFsVolumeInformation(new Buffer.PlainBuffer(outputBuffer, Endian.LE));
            } catch (Buffer.BufferException e) {
                throw new SMBRuntimeException(e);
            }
        }
    }

    private static StatusHandler ALREADY_DELETED_STATUS_HANDLER = new StatusHandler() {
        @Override
        public boolean isSuccess(long statusCode) {
            return statusCode == STATUS_DELETE_PENDING.getValue();
        }
    };

    /**
     * Remove the directory at the given path.
     */
    public void rmdir(String path, boolean recursive) throws SMBApiException {
        if (path == null || path.isEmpty()) {
            throw new IllegalArgumentException("rmdir: path should be non-null and non-empty");
        }
        try {
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
        } catch (SMBApiException sae) {
            if (ALREADY_DELETED_STATUS_HANDLER.isSuccess(sae.getStatusCode())) {
                return;
            }
            throw sae;
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
        } catch (SMBApiException sae) {
            if (ALREADY_DELETED_STATUS_HANDLER.isSuccess(sae.getStatusCode())) {
                return;
            }
            throw sae;
        }
    }

    public void deleteOnClose(SMB2FileId fileId) {
        setFileInformation(fileId, new FileDispositionInformation(true));
    }

    /**
     * The SecurityDescriptor(MS-DTYP 2.4.6 SECURITY_DESCRIPTOR) for the Given Path
     */
    public SecurityDescriptor getSecurityInfo(String path, Set<SecurityInformation> securityInfo) throws
        SMBApiException {
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
    public SecurityDescriptor getSecurityInfo(SMB2FileId fileId, Set<SecurityInformation> securityInfo) throws
        SMBApiException {

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
    public void setSecurityInfo(String path, Set<SecurityInformation> securityInfo, SecurityDescriptor
        securityDescriptor) throws SMBApiException {
        Set<AccessMask> accessMask = noneOf(AccessMask.class);
        if (securityInfo.contains(SecurityInformation.SACL_SECURITY_INFORMATION)) {
            accessMask.add(ACCESS_SYSTEM_SECURITY);
        }
        if (securityInfo.contains(SecurityInformation.OWNER_SECURITY_INFORMATION) || securityInfo.contains(SecurityInformation.GROUP_SECURITY_INFORMATION)) {
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
    public void setSecurityInfo(SMB2FileId fileId, Set<SecurityInformation> securityInfo, SecurityDescriptor
        securityDescriptor) throws SMBApiException {
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

    /**
     * A return object for the {@link #createFileAndResolve(SmbPath, SMB2ImpersonationLevel, Set, Set, Set, SMB2CreateDisposition, Set)} call.
     * <p>
     * This object wraps the {@link SMB2CreateResponse} and the actual {@link Share} which generated it if the path needed to be resolved.
     */
    static class SMB2CreateResponseContext {
        final SMB2CreateResponse resp;
        final DiskShare share;
        final SmbPath target;

        public SMB2CreateResponseContext(SMB2CreateResponse resp, SmbPath target, DiskShare share) {
            this.resp = resp;
            this.target = target;
            this.share = share;
        }
    }
}
