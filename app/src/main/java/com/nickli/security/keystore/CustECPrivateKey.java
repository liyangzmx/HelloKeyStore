package com.nickli.security.keystore;

import android.security.keystore.KeyProperties;
import android.util.Log;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

public class CustECPrivateKey implements ECPrivateKey {
    private ECParameterSpec spec;
    private String alias;
    private String format;

    public CustECPrivateKey(String alias, String format, ECParameterSpec spec) {
        this.alias = alias;
        this.spec = spec;
        this.format = format;
    }

    @Override
    public BigInteger getS() {
        return null;
    }

    public String getAlias() {
        return alias;
    }

    @Override
    public String getAlgorithm() {
        return KeyProperties.KEY_ALGORITHM_EC;
    }

    @Override
    public String getFormat() {
        return format;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }

    @Override
    public ECParameterSpec getParams() {
        return spec;
    }
}
