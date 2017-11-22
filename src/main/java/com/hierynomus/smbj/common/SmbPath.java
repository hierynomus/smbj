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

import java.util.Objects;

public class SmbPath {
    private final String hostname;
    private final String shareName;
    private final String path;

    public SmbPath(String hostname) {
        this(hostname, null, null);
    }

    public SmbPath(String hostname, String shareName) {
        this(hostname, shareName, null);
    }

    public SmbPath(String hostname, String shareName, String path) {
        this.shareName = shareName;
        this.hostname = hostname;
        this.path = path;
    }

    public SmbPath(SmbPath parent, String path) {
        this.hostname = parent.hostname;
        if (parent.shareName != null) {
            this.shareName = parent.shareName;
        } else {
            throw new IllegalArgumentException("Can only make child SmbPath of fully specified SmbPath");
        }
        if (parent.path != null) {
            this.path = parent.path + "\\" + path;
        } else {
            this.path = path;
        }
    }

    public String toUncPath() {
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

    @Override
    public String toString() {
        return toUncPath();
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
        if (split.length == 1) {
            return new SmbPath(split[0]);
        }
        if (split.length == 2) {
            return new SmbPath(split[0], split[1]);
        }
        return new SmbPath(split[0], split[1], split[2]);
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SmbPath smbPath = (SmbPath) o;
        return Objects.equals(hostname, smbPath.hostname) &&
            Objects.equals(shareName, smbPath.shareName) &&
            Objects.equals(path, smbPath.path);
    }

    @Override
    public int hashCode() {
        return Objects.hash(hostname, shareName, path);
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

    public boolean isOnSameHost(SmbPath other) {
        return other != null && Objects.equals(this.hostname, other.hostname);
    }

    public boolean isOnSameShare(SmbPath other) {
        return other != null && Objects.equals(this.hostname, other.hostname) && Objects.equals(this.shareName, other.shareName);
    }
}
