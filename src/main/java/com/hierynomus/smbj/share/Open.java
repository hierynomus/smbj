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

import java.io.Closeable;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2LockFlag;
import com.hierynomus.mssmb2.messages.submodule.SMB2LockElement;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.share.OperationBuckets.OperationBucket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Open<S extends Share> implements Closeable {
    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    protected S share;
    protected SMB2FileId fileId;
    protected SmbPath name;
    private OperationBuckets operationBuckets = new OperationBuckets();


    Open(SMB2FileId fileId, SmbPath name, S share) {
        this.fileId = fileId;
        this.name = name;
        this.share = share;
    }

    /**
     * 3.2.4.19 Application Requests Locking of an Array of Byte Ranges
     *
     * @return
     */
    public LockBuilder requestLock() {
        return new LockBuilder();
    }

    /***
     * Send a lock request for an Open. This could be lock/unlock operation.
     * 2.2.26 SMB2 LOCK Request
     *
     * @param lockElements List (an array) of LockCount (2.2.26.1 SMB2_LOCK_ELEMENT
     *                     Structure) structures.
     * @return Server response to lock request. 2.2.27 SMB2 LOCK Response
     */
    void lockRequest(List<SMB2LockElement> lockElements) {
        // [MS-SMB2].pdf 3.2.4.19 Application Requests Locking of an Array of Byte
        // Ranges
        // If any of the Booleans Open.ResilientHandle, Open.IsPersistent, or
        // Connection.SupportsMultiChannel is TRUE, ...
        // Otherwise the client MUST set LockSequenceIndex and LockSequenceNumber to 0.

        int sequenceNumber = 0, sequenceIndex = 0;
        if (share.getDialect() != SMB2Dialect.SMB_2_0_2) {
            OperationBucket b = operationBuckets.takeFreeBucket();
            sequenceNumber = b.getSequenceNumber();
            sequenceIndex = b.getIndex();
        }

        share.sendLockRequest(fileId, (short) sequenceNumber, sequenceIndex, lockElements);

        if (share.getDialect() != SMB2Dialect.SMB_2_0_2) {
            operationBuckets.freeBucket(sequenceIndex);
        }
    }

    public SMB2FileId getFileId() {
        return fileId;
    }

    public void close() {
        share.closeFileId(fileId);
    }

    public void closeSilently() {
        try {
            close();
        } catch (Exception e) {
            logger.warn("{} close failed for {},{},{}", this.getClass().getSimpleName(), name, share, fileId, e);
        }
    }

    public final class LockBuilder {
        private List<SMB2LockElement> elements = new ArrayList<>();

        public LockBuilder exclusiveLock(long offset, long length) {
            return exclusiveLock(offset, length, false);
        }

        public LockBuilder exclusiveLock(long offset, long length, boolean failImmediately) {
            Set<SMB2LockFlag> flags = EnumSet.of(SMB2LockFlag.SMB2_LOCKFLAG_EXCLUSIVE_LOCK);
            if (failImmediately) {
                flags.add(SMB2LockFlag.SMB2_LOCKFLAG_FAIL_IMMEDIATELY);
            }

            return addElement(offset, length, flags);
        }

        public LockBuilder sharedLock(long offset, long length) {
            return sharedLock(offset, length, false);
        }

        public LockBuilder sharedLock(long offset, long length, boolean failImmediately) {
            Set<SMB2LockFlag> flags = EnumSet.of(SMB2LockFlag.SMB2_LOCKFLAG_SHARED_LOCK);
            if (failImmediately) {
                flags.add(SMB2LockFlag.SMB2_LOCKFLAG_FAIL_IMMEDIATELY);
            }

            return addElement(offset, length, flags);
        }

        public LockBuilder unlock(long offset, long length) {
            return addElement(offset, length, EnumSet.of(SMB2LockFlag.SMB2_LOCKFLAG_UNLOCK));
        }

        private LockBuilder addElement(long offset, long length, Set<SMB2LockFlag> flags) {
            elements.add(new SMB2LockElement(offset, length, flags));
            return this;
        }

        public void send() {
            Open.this.lockRequest(elements);
        }
    }
}
