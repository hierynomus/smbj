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

import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.mssmb2.LeaseKey;
import com.hierynomus.mssmb2.messages.SMB2LeaseBreakAcknowledgment;
import com.hierynomus.mssmb2.messages.SMB2LeaseBreakNotification;

/**
 * Per-{@link Connection} lease table. An inbound lease break carries no session/tree id,
 * so the table must live on the connection where any break can resolve a {@link LeaseKey}
 * to its {@link LeaseEntry} (spec 06). A directory's lease key is minted <b>once per node
 * (path)</b> and reused (Apple's per-node key); the {@code path -> key} map also lets a
 * child open thread its parent directory's own lease key.
 */
public class LeaseManager {
    private static final Logger logger = LoggerFactory.getLogger(LeaseManager.class);

    private final ConcurrentMap<LeaseKey, LeaseEntry> byKey = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, LeaseKey> byPath = new ConcurrentHashMap<>();

    // A break must be resolved/acknowledged OFF the transport read thread: sending the ack is
    // itself an SMB2 request whose reply can only arrive on that same read thread.
    private final ExecutorService breakExecutor = Executors.newSingleThreadExecutor(new ThreadFactory() {
        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r, "smbj-lease-break");
            t.setDaemon(true);
            return t;
        }
    });
    private final AtomicInteger breaksHandled = new AtomicInteger(0);

    /** Stable per-node key: mint once per normalized path, reuse thereafter. */
    public LeaseKey leaseKeyForPath(String path) {
        return byPath.computeIfAbsent(normalize(path), p -> LeaseKey.random());
    }

    /** The lease key previously minted for {@code path}, or {@code null} if never opened. */
    public LeaseKey leaseKeyForExistingPath(String path) {
        return byPath.get(normalize(path));
    }

    /** The live lease entry for {@code path}, or {@code null} if none is registered. */
    public LeaseEntry getByPath(String path) {
        LeaseKey key = byPath.get(normalize(path));
        return key == null ? null : byKey.get(key);
    }

    /** Register an entry BEFORE sending its CREATE (a break can race the grant response). */
    public void register(LeaseEntry entry) {
        byKey.put(entry.getLeaseKey(), entry);
        byPath.putIfAbsent(normalize(entry.getPath()), entry.getLeaseKey());
    }

    /** Resolve an inbound break's lease key to its entry (spec 06). */
    public LeaseEntry lookup(LeaseKey key) {
        return byKey.get(key);
    }

    /** Drop the entry (no lease granted / handle closed). The node key in {@code byPath} is kept. */
    public void unregister(LeaseKey key) {
        byKey.remove(key);
    }

    /** Number of lease breaks fully handled (test/diagnostic hook). */
    public int getBreaksHandled() {
        return breaksHandled.get();
    }

    public void shutdown() {
        breakExecutor.shutdownNow();
    }

    /**
     * Entry point from the receive-thread break handler: dispatch the resolve/invalidate/ack
     * work OFF the read thread.
     */
    public void dispatchBreak(final SMB2LeaseBreakNotification notification) {
        breakExecutor.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    onBreak(notification);
                } catch (Throwable t) {
                    logger.error("Lease-break handling failed for {}", notification.getLeaseKey(), t);
                }
            }
        });
    }

    /** Resolve → epoch-check → invalidate → update state → ack (runs on {@link #breakExecutor}). */
    void onBreak(SMB2LeaseBreakNotification n) throws Exception {
        LeaseEntry entry = byKey.get(n.getLeaseKey());
        if (entry == null) {
            logger.debug("Lease break for unknown key {}, ignoring", n.getLeaseKey());
            return;
        }

        // Epoch-delta staleness guard (V2). NewEpoch == 0 (non-V2) => always apply.
        int delta = epochDelta(n.getNewEpoch(), entry.getEpoch());
        if (n.getNewEpoch() != 0 && delta <= 0) {
            logger.debug("Stale lease break (newEpoch {} <= stored {}), ignoring", n.getNewEpoch(), entry.getEpoch());
            return;
        }

        // Apply: invalidate cache, update stored state/epoch, mark broken.
        entry.invalidateCache();
        entry.setGrantedState(n.getNewLeaseState());
        if (n.getNewEpoch() != 0) {
            entry.setEpoch(n.getNewEpoch());
        }
        entry.setBroken(true);

        // Acknowledge if required (the RH-directory case). Ack state is a subset of NewLeaseState.
        if (n.isAckRequired() && entry.getSession() != null) {
            SMB2LeaseBreakAcknowledgment ack = new SMB2LeaseBreakAcknowledgment(
                entry.getDialect(), entry.getSession().getSessionId(), entry.getTreeId(),
                n.getLeaseKey(), n.getNewLeaseState());
            entry.getSession().send(ack); // normal (signed) send path; reply observed by the chain
            logger.debug("Acknowledged lease break for {} -> state {}", n.getLeaseKey(), n.getNewLeaseState());
        }
        breaksHandled.incrementAndGet();
    }

    /**
     * Epoch delta per Apple's smbfs model: 0 if equal, positive if newer (apply),
     * wrap-aware, -1 if stale/reordered (ignore).
     */
    static int epochDelta(int newEpoch, int storedEpoch) {
        if (newEpoch == storedEpoch) {
            return 0;
        }
        if (newEpoch > storedEpoch) {
            return newEpoch - storedEpoch;
        }
        // storedEpoch > newEpoch: a large gap means the 16-bit epoch wrapped (server is newer).
        if (storedEpoch - newEpoch > 32767) {
            return (0x10000 - storedEpoch) + newEpoch;
        }
        return -1; // stale / reordered
    }

    private static String normalize(String path) {
        return path == null ? "" : path.replace('/', '\\').toLowerCase(Locale.ROOT);
    }
}
