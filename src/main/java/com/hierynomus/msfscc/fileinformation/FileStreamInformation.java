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

import java.util.ArrayList;
import java.util.List;


public class FileStreamInformation implements FileQueryableInformation {

    private List<FileStreamInformationItem> streamList;

    FileStreamInformation(List<FileStreamInformationItem> streamList) {
        this.streamList = streamList;
    }

    public List<FileStreamInformationItem> getStreamList() {
        return streamList;
    }

    public List<String> getStreamNames() {
        List<String> nameList = new ArrayList<>();
        for (FileStreamInformationItem s : streamList) {
            nameList.add(s.getName());
        }
        return nameList;
    }


}
