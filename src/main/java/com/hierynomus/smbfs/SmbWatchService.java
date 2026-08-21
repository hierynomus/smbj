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

import com.hierynomus.smbj.share.DiskShare;

import java.io.IOException;
import java.nio.file.ClosedWatchServiceException;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A {@link WatchService} backed by pending SMB2 "change notify" requests, one per
 * registered directory. There is no server push notification to block on directly,
 * so {@link #poll(long, TimeUnit)}/{@link #take()} short-poll the registered keys.
 */
class SmbWatchService implements WatchService {

    private static final long POLL_INTERVAL_MILLIS = 10;

    private final DiskShare share;
    private final SmbFileSystem fileSystem;
    private final List<SmbWatchKey> watchKeys = new CopyOnWriteArrayList<>();
    private final AtomicBoolean closed = new AtomicBoolean(false);

    SmbWatchService(DiskShare share, SmbFileSystem fileSystem) {
        this.share = share;
        this.fileSystem = fileSystem;
    }

    @Override
    public void close() throws IOException {
        if (!closed.compareAndSet(false, true)) {
            return;
        }

        for (SmbWatchKey watchKey : watchKeys) {
            watchKey.cancel();
        }

        // the DiskShare/session is owned (and reused) by the ShareSource, this
        // service only owns the per-directory watch keys.
    }

    @Override
    public WatchKey poll() {
        requireOpen();

        for (SmbWatchKey watchKey : watchKeys) {
            if (watchKey.isReady()) {
                return watchKey;
            }
        }

        return null;
    }

    @Override
    public WatchKey poll(long timeout, TimeUnit unit) throws InterruptedException {
        requireOpen();

        long deadline = System.currentTimeMillis() + unit.toMillis(timeout);
        do {
            for (SmbWatchKey watchKey : watchKeys) {
                if (watchKey.isReady()) {
                    return watchKey;
                }
            }

            TimeUnit.MILLISECONDS.sleep(POLL_INTERVAL_MILLIS);
        } while (System.currentTimeMillis() < deadline && !closed.get());

        return null;
    }

    @Override
    public WatchKey take() throws InterruptedException {
        requireOpen();

        while (true) {
            for (SmbWatchKey watchKey : watchKeys) {
                if (watchKey.isReady()) {
                    return watchKey;
                }
            }

            if (closed.get()) {
                throw new ClosedWatchServiceException();
            }

            TimeUnit.MILLISECONDS.sleep(POLL_INTERVAL_MILLIS);
        }
    }

    WatchKey register(SmbPath path) {
        requireOpen();

        SmbWatchKey watchKey = new SmbWatchKey(path, this);
        watchKeys.add(watchKey);
        return watchKey;
    }

    void unregister(SmbWatchKey watchKey) {
        watchKeys.remove(watchKey);
    }

    private void requireOpen() {
        if (closed.get()) {
            throw new ClosedWatchServiceException();
        }
    }

    DiskShare getShare() {
        return share;
    }

    SmbFileSystem getFileSystem() {
        return fileSystem;
    }
}
