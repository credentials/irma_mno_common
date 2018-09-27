package org.irmacard.mno.common.util;

import com.google.gson.Gson;
import org.irmacard.mno.common.EDLDataMessage;
import org.irmacard.mno.common.EDlData;
import org.irmacard.mno.common.PassportData;
import org.irmacard.mno.common.PassportDataMessage;

public class GsonUtil extends org.irmacard.api.common.util.GsonUtil {
	static {
		org.irmacard.api.common.util.GsonUtil
				.addTypeAdapter(PassportDataMessage.class, new PassportDataMessageSerializer());
		org.irmacard.api.common.util.GsonUtil
				.addTypeAdapter(EDLDataMessage.class, new EDLDataMessageSerializer());
		org.irmacard.api.common.util.GsonUtil
				.addTypeAdapter(PassportData.class, new PassportDataSerializer());
		org.irmacard.api.common.util.GsonUtil
				.addTypeAdapter(EDlData.class, new EDLDataSerializer());
	}

	// This needs to be here as otherwise the above static constructor never gets called
	public static Gson getGson() {
		return org.irmacard.api.common.util.GsonUtil.getGson();
	}
}
