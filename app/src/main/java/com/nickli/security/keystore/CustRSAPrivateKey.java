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
        System.out.println("jms: getPrivateExponent");
        return null;
    }

    @Override
    public String getAlgorithm() {
        System.out.println("jms: getAlgorithm");
        return "RSA";
    }

    @Override
    public String getFormat() {
        System.out.println("jms: getFormat");
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        System.out.println("jms: getEncoded");
        return null;
    }

    @Override
    public BigInteger getModulus() {
        System.out.println("jms: getModulus");
        return modules;
    }
}
