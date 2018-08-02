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
package com.hierynomus.msfscc.fileinformation;

public class FileStreamInformationItem {

    private long size;
    private long allocSize;
    private String name;

    public FileStreamInformationItem(long size, long allocSize, String name) {
        this.size = size;
        this.allocSize = allocSize;
        this.name = name;
    }

    public long getSize() {
        return size;
    }

    public long getAllocSize() {
        return allocSize;
    }

    public String getName() {
        return name;
    }
}
