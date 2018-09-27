package org.irmacard.mno.common;


import org.irmacard.api.common.ClientQr;

public class DisclosureSessionMessage {
    private ClientQr qr;
    private String wsUri;
    private String proofUri;

    public DisclosureSessionMessage (ClientQr qr){
        this.qr = qr;
    }

    public DisclosureSessionMessage (ClientQr qr, String wsUri, String proofUri){
        this.qr = qr;
        this.wsUri = wsUri;
        this.proofUri = proofUri;
    }

    public ClientQr getQr() {
        return qr;
    }

    public void setQr(ClientQr qr) {
        this.qr = qr;
    }

    public String getWsUri() {
        return wsUri;
    }

    public void setWsUri(String wsUri) {
        this.wsUri = wsUri;
    }

    public String getProofUri() {
        return proofUri;
    }

    public void setProofUri(String proofUri) {
        this.proofUri = proofUri;
    }
}
