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
package com.hierynomus.smbfs;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.directory.FileNotifyInformation;
import com.hierynomus.mssmb2.SMB2CompletionFilter;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.mssmb2.messages.SMB2ChangeNotifyResponse;
import com.hierynomus.smbj.share.Directory;
import com.hierynomus.smbj.share.DiskShare;

import java.nio.file.ClosedWatchServiceException;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.Watchable;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A {@link WatchKey} for a single directory, backed by a pending SMB2 "change notify"
 * request ({@link Directory#watchAsync}). While a key is in the "signalled" state
 * (i.e. its notify request has completed) it must not be re-armed until the consumer
 * calls {@link #reset()}, matching the contract of {@link java.nio.file.WatchService}.
 */
class SmbWatchKey implements WatchKey {

    private final SmbPath path;
    private final SmbWatchService watchService;
    private final DiskShare diskShare;

    private final List<WatchEvent<?>> events = new CopyOnWriteArrayList<>();
    private final AtomicBoolean valid = new AtomicBoolean(true);
    private final AtomicBoolean signalled = new AtomicBoolean(false);

    private volatile Directory directory;
    private volatile Future<SMB2ChangeNotifyResponse> future;

    SmbWatchKey(SmbPath path, SmbWatchService watchService) {
        this.path = path;
        this.watchService = watchService;
        this.diskShare = watchService.getShare();

        if (!diskShare.isConnected()) {
            throw new ClosedWatchServiceException();
        }

        arm();
    }

    private void arm() {
        EnumSet<AccessMask> accessMask = EnumSet.of(AccessMask.FILE_LIST_DIRECTORY, AccessMask.FILE_READ_ATTRIBUTES, AccessMask.FILE_READ_EA);
        directory = diskShare.openDirectory(path.toString(), accessMask, null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null);
        future = directory.watchAsync(EnumSet.allOf(SMB2CompletionFilter.class), true);
    }

    /**
     * @return {@code true} if this key's pending notify request has completed and it
     * was not already signalled, i.e. it should now be handed out by
     * {@link SmbWatchService#poll()}/{@link SmbWatchService#take()}.
     */
    boolean isReady() {
        Future<SMB2ChangeNotifyResponse> f = future;
        if (!valid.get() || f == null || !f.isDone()) {
            return false;
        }

        if (!signalled.compareAndSet(false, true)) {
            return false;
        }

        harvest(f);
        return true;
    }

    private void harvest(Future<SMB2ChangeNotifyResponse> f) {
        try {
            SMB2ChangeNotifyResponse response = f.get();
            for (FileNotifyInformation info : response.getFileNotifyInfoList()) {
                events.add(new SmbWatchEvent(watchService.getFileSystem(), info));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (ExecutionException e) {
            // the notify request failed, e.g. because the share/connection was closed;
            // there is nothing more this key can observe.
            cancel();
        }
    }

    @Override
    public boolean isValid() {
        return valid.get();
    }

    @Override
    public List<WatchEvent<?>> pollEvents() {
        List<WatchEvent<?>> result = new ArrayList<>(events);
        events.clear();
        return result;
    }

    @Override
    public boolean reset() {
        if (!valid.get()) {
            return false;
        }

        if (!signalled.compareAndSet(true, false)) {
            // not currently signalled (e.g. reset() called twice) - nothing to do
            return valid.get();
        }

        events.clear();

        if (!diskShare.isConnected()) {
            cancel();
            return false;
        }

        arm();
        return true;
    }

    @Override
    public void cancel() {
        if (!valid.compareAndSet(true, false)) {
            return;
        }

        Future<SMB2ChangeNotifyResponse> f = future;
        if (f != null) {
            f.cancel(true);
        }

        Directory d = directory;
        if (d != null) {
            d.closeSilently();
        }

        watchService.unregister(this);
    }

    @Override
    public Watchable watchable() {
        return path;
    }
}
