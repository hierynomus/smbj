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
package com.hierynomus.msdfsc;

import com.hierynomus.smbj.common.SmbPath;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DFSPath {
    private final List<String> pathComponents;

    public DFSPath(String uncPath) {
        this.pathComponents = splitPath(uncPath);
    }

    public DFSPath(List<String> pathComponents) {
        this.pathComponents = pathComponents;
    }

    public List<String> getPathComponents() {
        return pathComponents;
    }

    public DFSPath replacePrefix(String prefixToReplace, String target) {
        List<String> componentsToReplace = splitPath(prefixToReplace);
        List<String> replacedComponents = new ArrayList<>();
        replacedComponents.addAll(splitPath(target));
        for (int i = componentsToReplace.size(); i < pathComponents.size(); i++) {
            replacedComponents.add(pathComponents.get(i));
        }
        return new DFSPath(replacedComponents);
    }

    public boolean hasOnlyOnePathComponent() {
        return pathComponents.size() == 1;
    }

    public boolean isSysVolOrNetLogon() {
        if (pathComponents.size() > 1) {
            String second = pathComponents.get(1);
            return "SYSVOL".equals(second) || "NETLOGON".equals(second);
        }
        return false;
    }

    public boolean isIpc() {
        if (pathComponents.size() > 1) {
            return "IPC$".equals(pathComponents.get(1));
        }
        return false;
    }

    static DFSPath from(SmbPath path) {
        List<String> pathComponents = new ArrayList<>();
        pathComponents.add(path.getHostname());
        if (path.getShareName() != null) {
            pathComponents.add(path.getShareName());
        }
        if (path.getPath() != null) {
            pathComponents.addAll(splitPath(path.getPath()));
        }
        return new DFSPath(pathComponents);
    }

    private static List<String> splitPath(String pathPart) {
        String splitPath = pathPart;
        if (pathPart.charAt(0) == '\\') {
            if (pathPart.charAt(1) == '\\') {
                splitPath = pathPart.substring(2);
            } else {
                splitPath = pathPart.substring(1);
            }
        }

        return Arrays.asList(splitPath.split("\\\\"));
    }

    public String toPath() {
        StringBuilder sb = new StringBuilder();
        for (String pathComponent : pathComponents) {
            sb.append("\\").append(pathComponent);
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return "DFSPath{" + pathComponents + "}";
    }
}
