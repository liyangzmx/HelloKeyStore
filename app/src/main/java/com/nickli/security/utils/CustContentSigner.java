package com.nickli.security.utils;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

class CustContentSigner implements ContentSigner {
    private final ByteArrayOutputStream outputStream;
    private Signature mSignature;
    private final PrivateKey mPrivateKey;
    private final boolean mIsRSA;
    private final String DEFUALT_PROVIDER = "AndroidKeyStoreBCWorkaround";

    public CustContentSigner(PrivateKey privateKey, boolean isRSA) {
        this.outputStream = new ByteArrayOutputStream();
        this.mPrivateKey = privateKey;
        mIsRSA = isRSA;
        try {
            if (mIsRSA)
                mSignature = Signature.getInstance("SHA256withRSA");
            else
                mSignature = Signature.getInstance("SHA256withECDSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        if (mIsRSA)
            return new AlgorithmIdentifier(
                    // 1.2.840.113549.1.1.11 is SHA256withRSA
                    new ASN1ObjectIdentifier("1.2.840.113549.1.1.11")
            );
        else
            return new AlgorithmIdentifier(
                    // 1.2.840.10045.4.3.2 is SHA256withECDSA
                    new ASN1ObjectIdentifier("1.2.840.10045.4.3.2")
            );
    }

    @Override
    public OutputStream getOutputStream() {
        return outputStream;
    }

    @Override
    public byte[] getSignature() {
        try {
            assert mSignature != null;
            System.out.println("outputStream len: " + outputStream.size());
            mSignature.initSign(mPrivateKey);
            mSignature.update(outputStream.toByteArray());
            return mSignature.sign();
        } catch (SignatureException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }
}
