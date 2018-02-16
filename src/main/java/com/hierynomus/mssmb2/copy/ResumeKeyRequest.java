package com.hierynomus.mssmb2.copy;

/**
 *
 */
public class ResumeKeyRequest {
    private static final long ctlCode = 0x00140078L;

    public static long getCtlCode() {
        return ctlCode;
    }

    public byte[] getData(){
        return new byte[0];
    }
}
