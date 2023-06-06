package com.nickli.security.keystore;

import com.nickli.security.utils.ECCKeyUtil;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;

public abstract class CustECSignatureSpi extends SignatureSpi {
    CustECPrivateKey mKey = null;
    ECCKeyUtil mECCKeyUtil = new ECCKeyUtil();
    byte[] mDigest = null;
    private static final String ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore";
    private Signature mSignature;
    private final String DEFUALT_PROVIDER = "AndroidKeyStoreBCWorkaround";

    protected abstract String getAlgothrim();

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        mSignature = null;
        try {
            mSignature = Signature.getInstance(getAlgothrim(), DEFUALT_PROVIDER);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new InvalidKeyException(e);
        }
        mSignature.initVerify(publicKey);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey instanceof CustECPrivateKey) {
            mSignature = null;
            mDigest = null;
            mKey = null;
            try {
                mSignature = Signature.getInstance(getAlgothrim(), DEFUALT_PROVIDER);
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                e.printStackTrace();
            }
            mKey = (CustECPrivateKey) privateKey;
            System.out.println("jms: CustECSignatureSpi.engineInitSign(PrivateKey: " + mKey.getAlias() + ")");
            PrivateKey key = mECCKeyUtil.getPrivateKey(mKey.getAlias());
            mSignature.initSign(key);
        } else {
            throw new InvalidKeyException("Unsupported key type, only support CustEcPrivateKey.");
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        System.out.println("jms: CustECSignatureSpi.engineUpdate(byte[] b)");
        engineUpdate(new byte[] {b}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
//        System.out.println("jms: CustECSignatureSpi.engineUpdate(byte[] b(len: " + b.length + "), int off(" + off + "), int len(" + len + "))");
        if (off < 0) {
            throw new SignatureException("sign data is error.");
        }

        if (len < 1 || off + len > b.length) {
            throw new SignatureException("sign data is error.");
        }

        mDigest = new byte[len];
        try {
            System.arraycopy(b, off, mDigest, 0, len);
        } catch (Exception e) {
            throw new SignatureException(e);
        }
        mSignature.update(mDigest);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        System.out.println("jms: CustECSignatureSpi.engineSign(algo: " + getAlgothrim() + ", key: " + mKey.getAlias() + ")");
        byte[] signData = new byte[0];
        try {
            signData = mSignature.sign();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return signData;
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
//        System.out.println("jms: engineVerify(byte[] sigBytes)");
        if (mSignature != null) {
            return mSignature.verify(sigBytes);
        }
        return false;
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        System.out.println("jms: engineSetParameter(String param, Object value)");
        throw new InvalidParameterException("Stub");
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        System.out.println("jms: engineGetParameter(String param)");
        throw new InvalidParameterException("Stub");
    }
}
