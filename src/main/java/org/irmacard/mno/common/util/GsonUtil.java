package org.irmacard.mno.common.util;

import com.google.gson.Gson;
import net.sf.scuba.smartcards.ProtocolCommand;
import net.sf.scuba.smartcards.ProtocolResponse;
import org.irmacard.mno.common.PassportDataMessage;

public class GsonUtil extends org.irmacard.api.common.util.GsonUtil {
	static {
		org.irmacard.api.common.util.GsonUtil
				.addTypeAdapter(PassportDataMessage.class, new PassportDataMessageSerializer());
		org.irmacard.api.common.util.GsonUtil
				.addTypeAdapter(ProtocolCommand.class, new ProtocolCommandSerializer());
		org.irmacard.api.common.util.GsonUtil
				.addTypeAdapter(ProtocolResponse.class, new ProtocolResponseSerializer());
	}

	// This needs to be here as otherwise the above static constructor never gets called
	public static Gson getGson() {
		return org.irmacard.api.common.util.GsonUtil.getGson();
	}
}
