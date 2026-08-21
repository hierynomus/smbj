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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

import com.hierynomus.msfscc.FileInformationClass;
import com.hierynomus.msfscc.fileinformation.FileDirectoryQueryableInformation;
import com.hierynomus.msfscc.fileinformation.FileInformation;
import com.hierynomus.msfscc.fileinformation.FileInformationFactory;

/**
 * Per-leased-directory enumeration cache (spec 07). Stores the last full listing keyed by
 * (path, informationClass, searchPattern) and serves it on a repeat {@code list()} while a
 * valid RH lease is held. Evicted synchronously when a lease break is observed (spec 06).
 *
 * <p>Correctness invariant: a cached enumeration is served only while a granted, un-broken RH
 * lease protects it; any break calls {@link #invalidateAll()} before the next {@code list()}
 * can observe it. Only the default ("list everything") query is cacheable — any real
 * {@code searchPattern} bypasses the cache.
 */
public class LeasedDirectoryCache {
    private final ConcurrentMap<CacheKey, List<? extends FileDirectoryQueryableInformation>> entries =
        new ConcurrentHashMap<>();
    // Diagnostics for deterministic hit/miss assertions in tests.
    private final AtomicLong serveHits = new AtomicLong();
    private final AtomicLong populates = new AtomicLong();

    // Process-wide aggregates (benchmark/diagnostics): cache hits vs real enumerations.
    private static final AtomicLong TOTAL_HITS = new AtomicLong();
    private static final AtomicLong TOTAL_POPULATES = new AtomicLong();

    public static long totalHits() {
        return TOTAL_HITS.get();
    }

    public static long totalPopulates() {
        return TOTAL_POPULATES.get();
    }

    public static void resetStats() {
        TOTAL_HITS.set(0);
        TOTAL_POPULATES.set(0);
    }

    /** Only the default/empty search pattern (list everything) is cacheable. */
    public static boolean isCacheable(String searchPattern) {
        return searchPattern == null || searchPattern.isEmpty();
    }

    private static <F extends FileInformation> FileInformationClass infoClassOf(Class<F> informationClass) {
        return FileInformationFactory.getDecoder(informationClass).getInformationClass();
    }

    /** @return the cached listing for the key, or {@code null} on a miss. Lock-free. */
    @SuppressWarnings("unchecked")
    public <I extends FileDirectoryQueryableInformation> List<I> serve(String path, Class<I> informationClass, String searchPattern) {
        if (!isCacheable(searchPattern)) {
            return null;
        }
        List<I> v = (List<I>) entries.get(new CacheKey(path, infoClassOf(informationClass), searchPattern));
        if (v != null) {
            serveHits.incrementAndGet();
            TOTAL_HITS.incrementAndGet();
        }
        return v;
    }

    /** Store an unmodifiable snapshot. Caller MUST hold a valid RH lease. */
    public <I extends FileDirectoryQueryableInformation> void populate(String path, Class<I> informationClass, String searchPattern, List<I> listing) {
        if (!isCacheable(searchPattern)) {
            return;
        }
        entries.put(new CacheKey(path, infoClassOf(informationClass), searchPattern),
            Collections.unmodifiableList(new ArrayList<I>(listing)));
        populates.incrementAndGet();
        TOTAL_POPULATES.incrementAndGet();
    }

    /** Evict everything (the break/downgrade hook). */
    public void invalidateAll() {
        entries.clear();
    }

    int size() {
        return entries.size();
    }

    /** Number of cache hits served (test/diagnostic). */
    public long getServeHits() {
        return serveHits.get();
    }

    /** Number of populates, i.e. real enumerations cached (test/diagnostic). */
    public long getPopulates() {
        return populates.get();
    }

    static final class CacheKey {
        private final String path;
        private final FileInformationClass informationClass;
        private final String searchPattern;

        CacheKey(String path, FileInformationClass informationClass, String searchPattern) {
            this.path = path == null ? "" : path.toLowerCase();
            this.informationClass = informationClass;
            this.searchPattern = searchPattern == null ? "" : searchPattern;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof CacheKey)) {
                return false;
            }
            CacheKey k = (CacheKey) o;
            return path.equals(k.path) && informationClass == k.informationClass && searchPattern.equals(k.searchPattern);
        }

        @Override
        public int hashCode() {
            return Objects.hash(path, informationClass, searchPattern);
        }
    }
}
