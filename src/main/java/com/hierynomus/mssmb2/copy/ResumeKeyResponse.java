package com.hierynomus.mssmb2.copy;

/**
 *
 */
public class ResumeKeyResponse {
    byte[] resumeKey;

    public ResumeKeyResponse(byte[] resumeKey) {
        this.resumeKey = resumeKey;
    }

    public byte[] getResumeKey() {
        return resumeKey;
    }
}
