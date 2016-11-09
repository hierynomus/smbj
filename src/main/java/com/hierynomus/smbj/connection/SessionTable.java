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

import com.hierynomus.smbj.session.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

public class SessionTable {
    private static final Logger logger = LoggerFactory.getLogger(SessionTable.class);
    private ReentrantLock lock = new ReentrantLock();
    private Map<Long, Session> lookup = new HashMap<>();

    public void registerSession(Long id, Session session) {
        lock.lock();
        try {
            lookup.put(id, session);
        } finally {
            lock.unlock();
        }
    }

    Session find(Long id) {
        lock.lock();
        try {
            return lookup.get(id);
        } finally {
            lock.unlock();
        }
    }
    
    public Session sessionClosed(Long id) {
        lock.lock();
        try {
            return lookup.remove(id);
        } finally {
            lock.unlock();
        }
    }

    boolean isActive(Long id) {
        lock.lock();
        try {
            return lookup.containsKey(id);
        } finally {
            lock.unlock();
        }
    }

    void closeRemainingSessions() {
        lock.lock();
        try {
            for (Long id : new HashSet<>(lookup.keySet())) {
                Session session = lookup.get(id);
                try {
                    session.close();
                } catch (IOException e) {
                    logger.error("Error closing session", e);
                }
            }
        } finally {
            lock.unlock();
        }
    }
}
