/*
 * Copyright (c) 2015, the IRMA Team
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

package org.irmacard.mno.common.util;

import com.google.gson.*;
import org.irmacard.mno.common.PassportDataMessage;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.DG2File;
import org.jmrtd.lds.SODFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Type;

import org.bouncycastle.util.encoders.Base64;
import org.jmrtd.lds.icao.DG5File;

public class PassportDataMessageSerializer
            implements JsonSerializer<PassportDataMessage>, JsonDeserializer<PassportDataMessage> {

        public JsonElement serialize(PassportDataMessage src, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject obj = new JsonObject();

            String sessionToken = src.getSessionToken();
            SODFile sodFile = src.getSodFile();
            DG1File dg1File = src.getDg1File();
            DG5File dg2File = src.getDg5File();
            byte[] dg14File = src.getEaFileAsBytes();
            byte[] dg15File = src.getAaFileAsBytes();
            byte[] response = src.getResponse();

            obj.addProperty("sessionToken", sessionToken);

            obj.addProperty("sodFile", context.serialize(sodFile.getEncoded()).getAsString());
            obj.addProperty("dg1File", context.serialize(dg1File.getEncoded()).getAsString());
            obj.addProperty("dg2File", context.serialize(dg2File.getEncoded()).getAsString());
            if (dg14File != null)
                obj.addProperty("dg14File", context.serialize(dg14File).getAsString());
            obj.addProperty("dg15File", context.serialize(dg15File).getAsString());

            obj.addProperty("response", context.serialize(response).getAsString());

            return obj;
        }

    @Override
    public PassportDataMessage deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        try {
            JsonObject map = json.getAsJsonObject();

            String sessionToken = map.get("sessionToken").getAsString();
            SODFile sodFile = new SODFile(toInputStream(map.get("sodFile")));
            DG1File dg1File = new DG1File(toInputStream(map.get("dg1File")));
            DG2File dg2File = new DG2File(toInputStream(map.get("dg2File")));
            byte[] dg15File = Base64.decode(map.get("dg15File").getAsString().getBytes());
            byte[] dg14File = null;
            if (map.get("dg14File") != null)
                dg14File = Base64.decode(map.get("dg14File").getAsString().getBytes());
            byte[] response = Base64.decode(map.get("response").getAsString().getBytes());

            PassportDataMessage msg = new PassportDataMessage(sessionToken);
            msg.setSodFile(sodFile);
            msg.setDg1File(dg1File);
            msg.setEaFile(dg14File);
            msg.setAaFile(dg15File);
            msg.setResponse(response);

            return msg;
        } catch (IOException e) {
            throw new JsonParseException(e);
        }
    }

    private static ByteArrayInputStream toInputStream(JsonElement el) {
        return new ByteArrayInputStream(Base64.decode(el.getAsString().getBytes()));
    }
}

