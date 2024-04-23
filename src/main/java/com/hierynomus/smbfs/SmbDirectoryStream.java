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
package com.hierynomus.smbfs;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.List;

class SmbDirectoryStream implements DirectoryStream<Path> {
    private final List<Path> list;

    private boolean closed;

    SmbDirectoryStream(List<Path> list) {
        this.list = list;
    }

    @Override
    public Iterator<Path> iterator() {
        if (closed)
            throw new IllegalStateException("closed");

        return list.iterator();
    }

    @Override
    public void close() throws IOException {
        closed = true;
    }
}
