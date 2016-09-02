/*
 * Copyright (c) 2015, Wouter Lueks
 * Copyright (c) 2015, Sietse Ringers
 * Copyright (c) 2015, Fabian van den Broek
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the IRMA project nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.irmacard.mno.common;

import org.jmrtd.lds.icao.DG14File;
import org.jmrtd.lds.icao.DG15File;
import org.jmrtd.lds.icao.DG1File;
import org.bouncycastle.crypto.SignerWithRecovery;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.ISO9796d2Signer;

import java.security.interfaces.RSAPublicKey;

public class PassportDataMessage extends DocumentDataMessage  {

    DG1File dg1File;    /* MRZ */
    private static final Integer aaDataGroupNumber = new Integer (15);
    private static final String pathToCertificates = "_passport_path";
    private static final String certificateFiles = "_passport_certs";

    public PassportDataMessage(String sessionToken, String imsi) {
        super(sessionToken,imsi);
    }

    public PassportDataMessage(String sessionToken, String imsi, byte[] challenge) {
        super(sessionToken,imsi,challenge);
    }

    @Override
    protected byte[] getPersonalDataFileAsBytes() {
        return dg1File.getEncoded();
    }

    @Override
    protected Integer getAADataGroupNumber() {
        return aaDataGroupNumber;
    }

    @Override
    public String getIssuingState() {
        return getDg1File().getMRZInfo().getIssuingState();
    }

    @Override
    protected String getPersonalDataFileAsString() {
        return dg1File.getMRZInfo().toString();
    }

    @Override
    protected SignerWithRecovery getRSASigner(){
        SignerWithRecovery signer = null;
        try {
            RSAEngine rsa = new RSAEngine();
            RSAPublicKey pub = (RSAPublicKey) aaFile.getPublicKey();
            RSAKeyParameters pubParameters = new RSAKeyParameters(false, pub.getModulus(), pub.getPublicExponent());
            signer = new ISO9796d2Signer(rsa, new SHA1Digest(), true);
            signer.init(false, pubParameters);
        } catch (Exception e /* response value is not correct*/){
            e.printStackTrace();
        }
        return signer;
    }

    @Override
    protected String getCertificateFilePath() {
        return pathToCertificates;
    }

    @Override
    protected String getCertificateFileList() {
        return certificateFiles;
    }

    public DG14File getDg14File() {
        return getEaFile();
    }

    public void setDg14File(DG14File dg14File) {
        setEaFile(dg14File);
    }

    public DG15File getDg15File() {
        return getAaFile();
    }

    public void setDg15File(DG15File dg15File) {
        setAaFile(dg15File);
    }

    public DG1File getDg1File() {
        return dg1File;
    }

    public void setDg1File(DG1File dg1File) {
        this.dg1File = dg1File;
    }

}
