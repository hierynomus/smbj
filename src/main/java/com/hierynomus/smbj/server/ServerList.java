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
package com.hierynomus.smbj.server;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

public class ServerList {
    private ReentrantLock lock = new ReentrantLock();
    private Map<String, Server> lookup = new HashMap<>();

    public Server lookup(String name) {
        lock.lock();
        try {
            return lookup.get(name);
        } finally {
            lock.unlock();
        }
    }

    public void registerServer(Server server) {
        lock.lock();
        try {
            lookup.put(server.getServerName(), server);
        } finally {
            lock.unlock();
        }
    }
}
