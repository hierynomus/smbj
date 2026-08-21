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

import com.hierynomus.msfscc.directory.FileNotifyInformation;

import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;

import static java.util.Collections.singletonList;

/**
 * A single change reported by an SMB "change notify" request for a directory
 * being watched via {@link SmbWatchService}.
 */
class SmbWatchEvent implements WatchEvent<Path> {

    private final SmbFileSystem fileSystem;
    private final FileNotifyInformation info;

    SmbWatchEvent(SmbFileSystem fileSystem, FileNotifyInformation info) {
        this.fileSystem = fileSystem;
        this.info = info;
    }

    @Override
    public Kind<Path> kind() {
        switch (info.getAction()) {
            case FILE_ACTION_RENAMED_NEW_NAME:
            case FILE_ACTION_ADDED:
                return StandardWatchEventKinds.ENTRY_CREATE;
            case FILE_ACTION_MODIFIED:
                return StandardWatchEventKinds.ENTRY_MODIFY;
            case FILE_ACTION_REMOVED_BY_DELETE:
            case FILE_ACTION_RENAMED_OLD_NAME:
            case FILE_ACTION_REMOVED:
                return StandardWatchEventKinds.ENTRY_DELETE;
            default:
                // stream-only changes (FILE_ACTION_*_STREAM) and other actions that have
                // no direct StandardWatchEventKinds equivalent are reported as a modify,
                // rather than failing the whole poll loop.
                return StandardWatchEventKinds.ENTRY_MODIFY;
        }
    }

    @Override
    public int count() {
        return 1;
    }

    @Override
    public Path context() {
        return SmbPath.of(fileSystem, null, singletonList(info.getFileName()));
    }
}
