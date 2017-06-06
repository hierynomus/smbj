package com.hierynomus.msdtyp;

import java.util.Date;

import static com.hierynomus.msdtyp.MsDataTypes.NANO100_TO_MILLI;
import static com.hierynomus.msdtyp.MsDataTypes.WINDOWS_TO_UNIX_EPOCH;

public class FileTime
{
    private final long windowsTimeStamp;

    public static FileTime fromDate(Date date) {
        return new FileTime(date.getTime() * NANO100_TO_MILLI + WINDOWS_TO_UNIX_EPOCH);
    }

    public static FileTime now() {
        return ofEpochMillis(System.currentTimeMillis());
    }

    public static FileTime ofEpochMillis(long epochMillis) {
        return new FileTime(epochMillis * NANO100_TO_MILLI + WINDOWS_TO_UNIX_EPOCH);
    }

    public FileTime(long windowsTimeStamp)
    {
        this.windowsTimeStamp = windowsTimeStamp;
    }

    public long getWindowsTimeStamp()
    {
        return windowsTimeStamp;
    }

    public long toEpochMillis()
    {
        return (windowsTimeStamp - WINDOWS_TO_UNIX_EPOCH) / NANO100_TO_MILLI;
    }

    public Date toDate() {
        return new Date(toEpochMillis());
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        FileTime fileTime = (FileTime) o;

        return windowsTimeStamp == fileTime.windowsTimeStamp;
    }

    @Override
    public int hashCode()
    {
        return (int) (windowsTimeStamp ^ (windowsTimeStamp >>> 32));
    }
}
