package com.nickli.security.keystore;

public class CustECDSASignatureSpi extends CustECSignatureSpi {
    private final String mAlgorithm;

    public CustECDSASignatureSpi(String mAlgorithm) {
        this.mAlgorithm = mAlgorithm;
    }

    @Override
    protected String getAlgothrim() {
        return mAlgorithm;
    }

    /**
     * NONEwithECDSA
     */
    public static final class NONE extends CustECDSASignatureSpi {
        public NONE() {
            super("NONEwithECDSA");
        }
    }

    /**
     * SHA1withECDSA
     */
    public static final class SHA1 extends CustECDSASignatureSpi {
        public SHA1() {
            super("SHA1withECDSA");
        }
    }

    /**
     * SHA256withECDSA
     */
    public static final class SHA256 extends CustECDSASignatureSpi {
        public SHA256() {
            super("SHA256withECDSA");
        }
    }

    /**
     * SHA384withECDSA
     */
    public static final class SHA384 extends CustECDSASignatureSpi {
        public SHA384() {
            super("SHA384withECDSA");
        }
    }

    /**
     * SHA512withECDSA
     */
    public static final class SHA512 extends CustECDSASignatureSpi {
        public SHA512() {
            super("SHA512withECDSA");
        }
    }
}
