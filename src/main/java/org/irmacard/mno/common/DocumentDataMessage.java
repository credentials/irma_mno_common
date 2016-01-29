package org.irmacard.mno.common;

public abstract class DocumentDataMessage extends BasicClientMessage {
	public DocumentDataMessage() {
		super();
	}

	public DocumentDataMessage(String sessionToken) {
		super(sessionToken);
	}

	public abstract PassportVerificationResult verify(byte[] challenge);
}
