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
    private String hostname;
    private String shareName;
    private String path;

    public SmbPath(String hostname, String shareName) {
        this.shareName = shareName;
        this.hostname = hostname;
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

    public void parse(String newPath) {
        int l;
        int n;
        int m;
        hostname = null;
        shareName = null;
        path = null;
        
        // newPath starts with one backslash
        if (newPath.startsWith("\\\\")) {
            l = 2;
        } else if (newPath.startsWith("\\")) {
            l = 1;
        } else {
            l = 0;
        }

        n = newPath.indexOf('\\',l);
        if (n > 0) {
            hostname = newPath.substring(l,n);
            m = newPath.indexOf('\\',n+1);
            if (m > 0) {
                shareName = newPath.substring(n+1,m);
                path = newPath.substring(m+1);
            } else {
                shareName = newPath.substring(n+1);
            }
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
