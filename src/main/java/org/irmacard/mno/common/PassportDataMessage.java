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

import net.sf.scuba.util.Hex;

import org.jmrtd.Util;
import org.jmrtd.lds.*;

import java.io.InputStream;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class PassportDataMessage extends DocumentDataMessage  {

    DG1File dg1File;    /* MRZ */
    private static final Integer aaDataGroupNumber = new Integer (15);
    private static final String rootCertFilePath = "";

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
    protected String getRootCertFilePath() {
        return rootCertFilePath;
    }

    @Override
    protected String getPersonalDataFileAsString() {
        return dg1File.getMRZInfo().toString();
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
