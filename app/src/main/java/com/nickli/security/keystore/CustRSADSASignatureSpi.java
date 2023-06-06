package com.nickli.security.keystore;

public class CustRSADSASignatureSpi extends CustRSASignatureSpi {
    private final String mAlgorithm;

    public CustRSADSASignatureSpi(String mAlgorithm) {
        this.mAlgorithm = mAlgorithm;
    }

    @Override
    protected String getAlgothrim() {
        return mAlgorithm;
    }

    /**
     * NONEwithRSA
     */
    public static final class NONE extends CustRSADSASignatureSpi {
        public NONE() {
            super("NONEwithRSA");
        }
    }

    /**
     * SHA1withRSA
     */
    public static final class SHA1 extends CustRSADSASignatureSpi {
        public SHA1() {
            super("SHA1withRSA");
        }
    }

    /**
     * SHA256withRSA
     */
    public static final class SHA256 extends CustRSADSASignatureSpi {
        public SHA256() {
            super("SHA256withRSA");
        }
    }

    /**
     * SHA384withRSA
     */
    public static final class SHA384 extends CustRSADSASignatureSpi {
        public SHA384() {
            super("SHA384withRSA");
        }
    }
}
