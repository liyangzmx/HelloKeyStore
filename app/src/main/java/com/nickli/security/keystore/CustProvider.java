package com.nickli.security.keystore;

import java.security.Provider;
import java.security.Security;

public class CustProvider extends Provider {
    private static final String PACKAGE_NAME = "com.nickli.security.keystore";
    private static final String PROVIDER_NAME = "Cust Provider";

    /**
     * Constructs a provider with the specified name, version number,
     * and information.
     *
     * @param name    the provider name.
     * @param version the provider version number.
     * @param info    a description of the provider and its services.
     */
    protected CustProvider() {
        super(PROVIDER_NAME, 1.0d, "Cust keystore security provider");

        // call AndroidKeyStore to sign
        putSignatureImpl("ECDSA", PACKAGE_NAME + ".CustECDSASignatureSpi$SHA1");
        put("Alg.Alias.Signature.ECDSA", "SHA1withECDSA");

        putSignatureImpl("SHA1withECDSA", PACKAGE_NAME + ".CustECDSASignatureSpi$SHA1");
        put("Alg.Alias.Signature.SHA1withECDSA", "SHA1withECDSA");

        putSignatureImpl("SHA256withECDSA", PACKAGE_NAME + ".CustECDSASignatureSpi$SHA256");
        put("Alg.Alias.Signature.SHA256withECDSA", "SHA256withECDSA");
        put("Alg.Alias.Signature.1.2.840.10045.4.3.2", "SHA256withECDSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.1with1.2.840.10045.2.1", "SHA256withECDSA");

        putSignatureImpl("SHA384withECDSA", PACKAGE_NAME + ".CustECDSASignatureSpi$SHA384");
        put("Alg.Alias.Signature.SHA384withECDSA", "SHA384withECDSA");

        putSignatureImpl("SHA512withECDSA", PACKAGE_NAME + ".CustECDSASignatureSpi$SHA512");
        put("Alg.Alias.Signature.SHA512withECDSA", "SHA512withECDSA");

        putSignatureImpl("NONEwithECDSA", PACKAGE_NAME + ".CustECDSASignatureSpi$NONE");
        put("Alg.Alias.Signature.NONEwithECDSA", "NONEwithECDSA");

        // call AndroidKeyStore to encrypt
        putCipherImpl("RSA/ECB/NoPadding", PACKAGE_NAME + ".CustRSACipherSpi$ARSA_ECB_NoPadding");
        put("Alg.Alias.Cipher.RSA/None/NoPadding", "RSA/ECB/NoPadding");
    }

    public static void installAsDefault() {
        Provider[] providers = Security.getProviders("SSLContext.TLS");
        // Mustbe first ???
//        if (providers != null && "AndroidOpenSSL".equals(providers[0].getName())) {
//            Security.addProvider(new CustProvider());
//            System.out.println("jms: add sky keystore after android openssl.");
//            return;
//        }
        int ret = Security.insertProviderAt(new CustProvider(), 1);
        System.out.println("jms: add sky keystore at first. ret: " + ret);
    }

    public static void install() {
        Security.addProvider(new CustProvider());
    }

    private void putSignatureImpl(String algorithm, String implClass) {
        put("Signature." + algorithm, implClass);
    }

    private void putCipherImpl(String algorithm, String implClass) {
        put("Cipher." + algorithm, implClass);
        // put("Cipher." + algorithm + " SupportedKeyClasses", "com.skyui.security.keystore.SkyKeyStorePrivateKey|com.skyui.security.keystore.SkyKeyStorePublicKey");
    }
}
