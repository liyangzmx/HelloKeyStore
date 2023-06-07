package com.nickli.security.keystore;

public class CustRSACipherSpi extends CustCipherSpiBase{
    private String mAlgorithm;

    public CustRSACipherSpi(String algorithm) {
        mAlgorithm = algorithm;
    }

    @Override
    protected String getAlgothrim() {
        return mAlgorithm;
    }

    /**
     * AES256 GCM NoPadding
     */
    public static final class ARSA_ECB_NoPadding extends CustRSACipherSpi {
        public ARSA_ECB_NoPadding() {
            super("RSA/ECB/NoPadding");
        }
    }
}
