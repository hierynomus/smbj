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
package com.hierynomus.smbj.connection;

import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.mssmb2.LeaseKey;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.Directory;
import com.hierynomus.smbj.share.LeasedDirectoryCache;

/**
 * Client-side state for one directory lease. Registered in the {@link LeaseManager}
 * <b>before</b> the CREATE is sent (a break can race the grant response), then updated
 * with the server-granted state once the response arrives. The receive thread (lease-break
 * handler) and the caller thread both touch the mutable fields, hence {@code volatile}.
 */
public class LeaseEntry {
    private static final Logger logger = LoggerFactory.getLogger(LeaseEntry.class);
    private final LeaseKey leaseKey;
    private final LeaseKey parentLeaseKey; // nullable
    private final long requestedState;
    private final String shareName;
    private final String path;

    private volatile long grantedState;
    private volatile int epoch;
    private volatile SMB2FileId fileId;
    private volatile boolean granted;
    private volatile boolean broken;

    private LeaseManager leaseManager;
    // Guarded by the registering manager's lock. Includes CREATEs in flight until their
    // Directory takes ownership, keeping lease-break routing until the final close.
    private int handleReferences;

    // For sending the lease-break acknowledgment on the owning session (signed).
    private volatile Session session;
    private volatile long treeId;
    private volatile SMB2Dialect dialect;

    // Bumped on every invalidation so an in-flight query cannot refill an obsolete cache.
    private final AtomicInteger cacheGeneration = new AtomicInteger(0);
    private final LeasedDirectoryCache cache = new LeasedDirectoryCache();
    // A dedicated, kept-open directory handle owned by DiskShare.list() for cache enumeration.
    // It is NEVER handed to the application, so the app closing its own handles cannot close it.
    private volatile Directory cacheDirectory;

    public LeaseEntry(LeaseKey leaseKey, LeaseKey parentLeaseKey, long requestedState, String shareName, String path) {
        this.leaseKey = leaseKey;
        this.parentLeaseKey = parentLeaseKey;
        this.requestedState = requestedState;
        this.shareName = LeaseManager.normalizeShare(shareName);
        this.path = path;
    }

    public LeaseEntry(LeaseKey leaseKey, LeaseKey parentLeaseKey, long requestedState, String path) {
        this(leaseKey, parentLeaseKey, requestedState, null, path);
    }

    public String getShareName() {
        return shareName;
    }

    public LeaseKey getLeaseKey() {
        return leaseKey;
    }

    public LeaseKey getParentLeaseKey() {
        return parentLeaseKey;
    }

    public long getRequestedState() {
        return requestedState;
    }

    public String getPath() {
        return path;
    }

    public long getGrantedState() {
        return grantedState;
    }

    public void setGrantedState(long grantedState) {
        this.grantedState = grantedState;
    }

    public int getEpoch() {
        return epoch;
    }

    public void setEpoch(int epoch) {
        this.epoch = epoch;
    }

    public SMB2FileId getFileId() {
        return fileId;
    }

    public void setFileId(SMB2FileId fileId) {
        this.fileId = fileId;
    }

    public boolean isGranted() {
        return granted;
    }

    public void setGranted(boolean granted) {
        this.granted = granted;
    }

    public boolean isBroken() {
        return broken;
    }

    public void setBroken(boolean broken) {
        this.broken = broken;
    }

    void retainReference(LeaseManager manager) {
        leaseManager = manager;
        handleReferences++;
    }

    int releaseReference() {
        return --handleReferences;
    }

    /** Release this directory handle's reservation on the connection that registered it. */
    public void handleClosed() {
        leaseManager.release(this);
    }

    /** Observe an asynchronous CLOSE away from transport and lease-break threads. */
    public void handleClosePending(Runnable completion) {
        leaseManager.dispatchClose(completion);
    }

    public Session getSession() {
        return session;
    }

    public long getTreeId() {
        return treeId;
    }

    public SMB2Dialect getDialect() {
        return dialect;
    }

    /** Record the open's owning session/tree/dialect so a break can be acknowledged. */
    public void setOwner(Session session, long treeId, SMB2Dialect dialect) {
        this.treeId = treeId;
        this.dialect = dialect;
        this.session = session;
    }

    public int getCacheGeneration() {
        return cacheGeneration.get();
    }

    public LeasedDirectoryCache getCache() {
        return cache;
    }

    public Directory getCacheDirectory() {
        return cacheDirectory;
    }

    public synchronized void setCacheDirectory(Directory cacheDirectory) {
        this.cacheDirectory = cacheDirectory;
    }

    /** Detach only the handle that the caller used; another query may have installed a new one. */
    public synchronized void clearCacheDirectory(Directory expectedDirectory) {
        if (cacheDirectory == expectedDirectory) {
            cacheDirectory = null;
        }
    }

    /** Evict the cached enumeration tied to this lease and bump the generation (break/downgrade hook).
     *  Also closes and nulls the kept-open cache-enumeration handle so the server can reclaim it. */
    public int invalidateCache() {
        return invalidateCache(false);
    }

    /** Send CLOSE before acknowledging a break, without waiting for its response on the break executor. */
    int invalidateCacheNoWait() {
        return invalidateCache(true);
    }

    private int invalidateCache(boolean closeNoWait) {
        Directory old;
        int generation;
        // Cache publication uses this same monitor for its generation check and populate.
        synchronized (this) {
            generation = cacheGeneration.incrementAndGet();
            cache.invalidateAll();
            old = cacheDirectory;
            cacheDirectory = null;
        }
        // CLOSE performs network I/O and must not hold up cache publication or invalidation.
        if (old != null) {
            if (closeNoWait) {
                try {
                    old.closeNoWait();
                } catch (RuntimeException e) {
                    logger.warn("Cached directory close failed for {}", path, e);
                }
            } else {
                old.closeSilently();
            }
        }
        return generation;
    }
}
