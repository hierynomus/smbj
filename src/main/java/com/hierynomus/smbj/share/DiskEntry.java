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

import com.hierynomus.msdtyp.SecurityDescriptor;
import com.hierynomus.msdtyp.SecurityInformation;
import com.hierynomus.msfscc.fileinformation.FileAllInformation;
import com.hierynomus.msfscc.fileinformation.FileQueryableInformation;
import com.hierynomus.msfscc.fileinformation.FileRenameInformation;
import com.hierynomus.msfscc.fileinformation.FileSettableInformation;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.protocol.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.util.EnumSet;
import java.util.Set;

public abstract class DiskEntry implements Closeable {
    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    protected DiskShare share;
    protected SMB2FileId fileId;
    protected String fileName;

    DiskEntry(SMB2FileId fileId, DiskShare share, String fileName) {
        this.share = share;
        this.fileId = fileId;
        this.fileName = fileName;
    }

    public void close() {
        share.closeFileId(fileId);
    }

    public SMB2FileId getFileId() {
        return fileId;
    }

    public FileAllInformation getFileInformation() throws SMBApiException, TransportException {
        return getFileInformation(FileAllInformation.class);
    }

    public <F extends FileQueryableInformation> F getFileInformation(Class<F> informationClass) throws SMBApiException {
        return share.getFileInformation(fileId, informationClass);
    }

    public <F extends FileSettableInformation> void setFileInformation(F information) {
        share.setFileInformation(fileId, information);
    }

    public SecurityDescriptor getSecurityInformation(Set<SecurityInformation> securityInfo) throws SMBApiException {
        return share.getSecurityInfo(fileId, securityInfo);
    }

    public void setSecurityInformation(SecurityDescriptor securityDescriptor) throws SMBApiException {
        EnumSet<SecurityInformation> securityInfo = EnumSet.noneOf(SecurityInformation.class);
        if (securityDescriptor.getOwnerSid() != null) {
            securityInfo.add(SecurityInformation.OWNER_SECURITY_INFORMATION);
        }

        if (securityDescriptor.getGroupSid() != null) {
            securityInfo.add(SecurityInformation.GROUP_SECURITY_INFORMATION);
        }

        if (securityDescriptor.getControl().contains(SecurityDescriptor.Control.DP)) {
            securityInfo.add(SecurityInformation.DACL_SECURITY_INFORMATION);
        }

        if (securityDescriptor.getControl().contains(SecurityDescriptor.Control.SP)) {
            securityInfo.add(SecurityInformation.SACL_SECURITY_INFORMATION);
        }

        share.setSecurityInfo(fileId, securityInfo, securityDescriptor);
    }

    public void setSecurityInformation(SecurityDescriptor securityDescriptor, Set<SecurityInformation> securityInfo) throws SMBApiException {
        share.setSecurityInfo(fileId, securityInfo, securityDescriptor);
    }

    public void rename(String newName) throws SMBApiException {
        this.rename(newName, false);
    }

    public void rename(String newName, boolean replaceIfExist) throws SMBApiException {
        this.rename(newName, replaceIfExist, 0);
    }

    public void rename(String newName, boolean replaceIfExist, long rootDirectory) throws SMBApiException {
        FileRenameInformation renameInfo = new FileRenameInformation(replaceIfExist, rootDirectory, newName);
        this.setFileInformation(renameInfo);
    }

    /**
     * Sends a control code directly to a specified device driver, causing the corresponding device to perform the
     * corresponding operation.
     *
     * @param ctlCode  the control code
     * @param isFsCtl  true if the control code is an FSCTL; false if it is an IOCTL
     * @param inData   the control code dependent input data
     * @param inOffset the offset in <code>inData</code> where the input data starts
     * @param inLength the number of bytes from <code>inData</code> to send, starting at <code>offset</code>
     * @return the response data or <code>null</code> if the control code did not produce a response
     */
    public byte[] ioctl(int ctlCode, boolean isFsCtl, byte[] inData, int inOffset, int inLength) {
        return share.ioctl(fileId, ctlCode, isFsCtl, inData, inOffset, inLength);
    }

    /**
     * Sends a control code directly to a specified device driver, causing the corresponding device to perform the
     * corresponding operation.
     *
     * @param ctlCode   the control code
     * @param isFsCtl   true if the control code is an FSCTL; false if it is an IOCTL
     * @param inData    the control code dependent input data
     * @param inOffset  the offset in <code>inData</code> where the input data starts
     * @param inLength  the number of bytes from <code>inData</code> to send, starting at <code>inOffset</code>
     * @param outData   the buffer where the response data should be written
     * @param outOffset the offset in <code>outData</code> where the output data should be written
     * @param outLength the maximum amount of data to write in <code>outData</code>, starting at <code>outOffset</code>
     * @return the number of bytes written to <code>outData</code>
     */
    public int ioctl(int ctlCode, boolean isFsCtl, byte[] inData, int inOffset, int inLength, byte[] outData, int outOffset, int outLength) {
        return share.ioctl(fileId, ctlCode, isFsCtl, inData, inOffset, inLength, outData, outOffset, outLength);
    }

    public void flush() {
        share.flush(fileId);
    }

    public void deleteOnClose() {
        share.deleteOnClose(fileId);
    }

    public void closeSilently() {
        try {
            close();
        } catch (Exception e) {
            logger.warn("File close failed for {},{},{}", fileName, share, fileId, e);
        }
    }
}
