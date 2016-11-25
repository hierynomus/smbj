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
package com.hierynomus.smbj.session;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import com.hierynomus.smbj.share.TreeConnect;

/**
 * [MS-SMB2].pdf 3.2.1.3 Per Session
 * <p>
 * A table of tree connects, as specified in section 3.2.1.4. The table MUST allow lookup by both TreeConnect.TreeConnectId and by share name.
 */
class TreeConnectTable {
    private ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private Map<Long, TreeConnect> lookupById = new HashMap<>();
    private Map<String, TreeConnect> lookupByShareName = new HashMap<>();

    void register(TreeConnect treeConnect) {
        lock.writeLock().lock();
        try {
            lookupById.put(treeConnect.getTreeId(), treeConnect);
            lookupByShareName.put(treeConnect.getShareName(), treeConnect);
        } finally {
            lock.writeLock().unlock();
        }
    }

    Collection<TreeConnect> getOpenTreeConnects() {
        lock.readLock().lock();
        try {
            return new ArrayList<>(lookupById.values());
        } finally {
            lock.readLock().unlock();
        }
    }

    TreeConnect getTreeConnect(long treeConnectId) {
        lock.readLock().lock();
        try {
            return lookupById.get(treeConnectId);
        } finally {
            lock.readLock().unlock();
        }
    }

    TreeConnect getTreeConnect(String shareName) {
        lock.readLock().lock();
        try {
            return lookupByShareName.get(shareName);
        } finally {
            lock.readLock().unlock();
        }
    }

    void closed(long treeConnectId) {
        lock.writeLock().lock();
        try {
            TreeConnect treeConnect = lookupById.remove(treeConnectId);
            if (treeConnect != null) {
                lookupByShareName.remove(treeConnect.getShareName());
            }
        } finally {
            lock.writeLock().unlock();
        }
    }
}
