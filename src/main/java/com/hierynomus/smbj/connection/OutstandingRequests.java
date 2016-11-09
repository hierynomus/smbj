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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import com.hierynomus.smbj.common.SMBRuntimeException;

class OutstandingRequests {
    private ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private Map<Long, Request> lookup = new HashMap<>();
    private Map<UUID, Request> cancelLookup = new HashMap<>();

    boolean isOutstanding(Long messageId) {
        lock.readLock().lock();
        try {
            return lookup.containsKey(messageId);
        } finally {
            lock.readLock().unlock();
        }
    }

    Request getRequestByMessageId(Long messageId) {
        lock.readLock().lock();
        try {
            return lookup.get(messageId);
        } finally {
            lock.readLock().unlock();
        }
    }

    Request getRequestByCancelId(UUID cancelId) {
        lock.readLock().lock();
        try {
            return cancelLookup.get(cancelId);
        } finally {
            lock.readLock().unlock();
        }
    }

    Request receivedResponseFor(Long messageId) {
        lock.writeLock().lock();
        try {
            Request r = lookup.remove(messageId);
            if (r == null) {
                throw new SMBRuntimeException("Unable to find outstanding request for messageId " + messageId);
            }
            cancelLookup.remove(r.getCancelId());
            return r;
        } finally {
            lock.writeLock().unlock();
        }
    }

    void registerOutstanding(Request request) {
        lock.writeLock().lock();
        try {
            lookup.put(request.getMessageId(), request);
            cancelLookup.put(request.getCancelId(), request);
        } finally {
            lock.writeLock().unlock();
        }
    }

    void handleError(Throwable t) {
        lock.writeLock().lock();
        try {
            for (Long id : new HashSet<>(lookup.keySet())) {
                Request removed = lookup.remove(id);
                cancelLookup.remove(removed.getCancelId());
                removed.getPromise().deliverError(t);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }
}
