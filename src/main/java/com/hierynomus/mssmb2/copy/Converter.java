package com.hierynomus.mssmb2.copy;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

/**
 *
 */
public class Converter {
    public static ResumeKeyResponse decodeResumeKey(byte[] bytes) throws Buffer.BufferException {
        SMBBuffer in = new SMBBuffer(bytes);
        byte[] resumeKey = in.readRawBytes(24);
        return new ResumeKeyResponse(resumeKey);
    }

    /**
     *
     * @param request
     * @return
     */
    public static byte[] encodeCopyChunkRequest(CopyChunkRequest request){
        SMBBuffer smbBuffer = new SMBBuffer();
        smbBuffer.putRawBytes(request.getResumeKey());  //RESUME KEY
        smbBuffer.putUInt32(request.getChunks().size());    //CHUNK COUNT
        smbBuffer.putUInt32(0l);    //reserved
        for (CopyChunkRequest.Chunk chunk : request.getChunks()){
            smbBuffer.putUInt64(chunk.getSrcOffset());//source offset
            smbBuffer.putUInt64(chunk.getTgtOffset());//target offset
            smbBuffer.putUInt32(chunk.getLength()); //length
            smbBuffer.putUInt32(0); //reserved 0 always
        }
        return smbBuffer.getCompactData();
    }

    public static CopyChunkResponse decodeCopyChunkResponse(byte[] outputBuffer) throws Buffer.BufferException {
        SMBBuffer in = new SMBBuffer(outputBuffer);
        return new CopyChunkResponse(in.readUInt32(),in.readUInt32(),in.readUInt32());
    }
}
