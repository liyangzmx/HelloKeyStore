package com.nickli.security.keystore;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

public class CustRSAPrivateKey implements RSAPrivateKey {
    public String getAlias() {
        return alias;
    }

    private final String alias;
    private final BigInteger modules;

    public CustRSAPrivateKey(String alias, BigInteger modules) {
        this.alias = alias;
        this.modules = modules;
    }

    @Override
    public BigInteger getPrivateExponent() {
        return null;
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public String getFormat() {
        return "PKCS#1";
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }

    @Override
    public BigInteger getModulus() {
        return modules;
    }
}