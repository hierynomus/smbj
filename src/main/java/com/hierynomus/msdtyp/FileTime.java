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
package com.hierynomus.msdtyp;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import static com.hierynomus.msdtyp.MsDataTypes.NANO100_TO_MILLI;
import static com.hierynomus.msdtyp.MsDataTypes.WINDOWS_TO_UNIX_EPOCH;

public class FileTime {
    private final long windowsTimeStamp;

    public static FileTime fromDate(Date date) {
        return new FileTime(date.getTime() * NANO100_TO_MILLI + WINDOWS_TO_UNIX_EPOCH);
    }

    public static FileTime now() {
        return ofEpochMillis(System.currentTimeMillis());
    }

    public static FileTime ofEpochMillis(long epochMillis) {
        return ofEpoch(epochMillis, TimeUnit.MILLISECONDS);
    }

    public static FileTime ofEpoch(long epoch, TimeUnit unit) {
        long nanoEpoch = TimeUnit.NANOSECONDS.convert(epoch, unit);
        return new FileTime(nanoEpoch / 100 + WINDOWS_TO_UNIX_EPOCH);
    }

    public FileTime(long windowsTimeStamp) {
        this.windowsTimeStamp = windowsTimeStamp;
    }

    public long getWindowsTimeStamp() {
        return windowsTimeStamp;
    }

    public long toEpochMillis() {
        return toEpoch(TimeUnit.MILLISECONDS);
    }

    public long toEpoch(TimeUnit unit) {
        return unit.convert((windowsTimeStamp - WINDOWS_TO_UNIX_EPOCH) * 100, TimeUnit.NANOSECONDS);
    }

    public Date toDate() {
        return new Date(toEpochMillis());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        FileTime fileTime = (FileTime) o;

        return windowsTimeStamp == fileTime.windowsTimeStamp;
    }

    @Override
    public int hashCode() {
        return (int) (windowsTimeStamp ^ (windowsTimeStamp >>> 32));
    }
}
