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
package com.hierynomus.smbj.common;

public class SmbPath {
    private final String hostname;
    private final String shareName;
    private final String path;

    public SmbPath(String hostname, String shareName) {
        this(hostname, shareName, null);
    }

    public SmbPath(String hostname, String shareName, String path) {
        this.shareName = shareName;
        this.hostname = hostname;
        this.path = path;
    }
    
    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("\\\\");
        b.append(hostname);
        if (shareName != null) {
            // Clients can either pass \share or share
            if (shareName.charAt(0) != '\\') {
                b.append("\\");
            }
            b.append(shareName);
            if (path != null) {
                b.append("\\").append(path);
            }
        }
        return b.toString();
    }

    public static SmbPath parse(String path) {
        String splitPath = path;
        if (path.charAt(0) == '\\') {
            if (path.charAt(1) == '\\') {
                splitPath = path.substring(2);
            } else {
                splitPath = path.substring(1);
            }
        }

        String[] split = splitPath.split("\\\\", 3);
        if (split.length == 2) {
            return new SmbPath(split[0], split[1]);
        } else {
            return new SmbPath(split[0], split[1], split[2]);
        }
    }

    public String getHostname() {
        return hostname;
    }

    public String getShareName() {
        return shareName;
    }

    public String getPath() {
        return path;
    }
}
