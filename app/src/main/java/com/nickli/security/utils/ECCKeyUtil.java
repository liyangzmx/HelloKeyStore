package com.nickli.security.utils;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import androidx.annotation.RequiresApi;

import com.nickli.security.keystore.CustECPrivateKey;
import com.nickli.security.keystore.CustRSAPrivateKey;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

public class ECCKeyUtil {
    private static final String ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String KEY_ALIAS = "my_key_alias";
    private static final String PLT_KEY_ALIAS = "platform_key_alias";

    private static final String APP_SECRET = "d68397c4fb671bc024e24e1964b067cc35388818";
    private static final String FUSE_ROOT_HASH = "df5931e5602ae6fca6d2de3d567c7a44708d19e8154304fea " +
            "                9fe417d16cae732697cf8d06685eed9d397383637a0a898ff9bb4c17bd8800e5788545b4ca25426";
    private static final int OEM_ID = 0x01B4;
    private static final int JTAG_ID = 0x14725836;
    private static final String SALT = "147259ea \n";
    private static final int OKM_LEN = 256;
    private static final String RD_PUB_EPHEMERAL_TEST = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3JZcof/4ONKBqHyQ0g+2i36Ot0BwXZPMZor0xDguZQL711xfWR6y7TjJ5u3TgdEVn9iSKhrqEf8mrtr5ZpfrUw==";
    private static final String RD_PUB_EPHEMERAL_PROD = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESc3DAILa0RFoUzsF+6rUBmmcp9eFkvyMjVqN++5bG/MBLpsT0PQasoJ6cEGBLWsAk8bQdN0nExgJvr5Zjk8npQ==";

    private static final boolean DEBUG = true;

    private KeyStore mKeyStore;
    private KeyStore.PrivateKeyEntry mPrivateKeyEntry;
    private PrivateKey mPrivatekey;
    private PublicKey mPublicKey;

    private static final byte[] FAKE_PRI_KEY_ENCODED = {48, -127, -121, 2, 1, 0, 48, 19, 6, 7,
            42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72, -50, 61, 3, 1, 7, 4, 109, 48, 107, 2, 1,
            1, 4, 32, 53, 19, -18, -26, 11, 60, -57, -38, 77, -115, -15, -40, -67, -114, -113, 59,
            127, 81, -102, -78, -43, 19, -86, -128, 28, -69, -126, -106, -30, 39, -75, 42, -95, 68,
            3, 66, 0, 4, -114, -89, -115, 64, 1, -109, 17, 121, -8, -11, 18, 85, -24, -2, 0, -25,
            105, 87, -33, -87, -121, 69, -84, -8, 46, -100, 49, 43, 53, -59, 89, -44, -3, 70, 117,
            -126, 122, -120, -126, 112, -60, 55, -99, 125, -52, 81, 118, -77, -119, -26, 1, 107,
            -114, 4, 69, 96, 116, 115, -114, -128, 86, 47, 112, -81};
    private static final String TLS_PRI_KEY_FORMAT = "PKCS#8";

    public void importCertCA(String caAlias, X509Certificate caCert) {
        KeyStore systemKeyStore = null;
        try {
            systemKeyStore = KeyStore.getInstance("AndroidCAStore");
            systemKeyStore.load(null);
            systemKeyStore.setCertificateEntry(caAlias, caCert);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void importCertForKey(String alias, X509Certificate certificate) {
        System.out.println("jms: importCertForKey(for: " + alias + ")");
        KeyStore.PrivateKeyEntry privateKeyEntry = null;
        try {
            privateKeyEntry = (KeyStore.PrivateKeyEntry) mKeyStore.getEntry(alias, null);
            if (privateKeyEntry != null) {
                mKeyStore.setCertificateEntry(alias, certificate);
                System.out.println("jms: importCert for key: " + alias + ": OK");
            } else {
                System.out.println("jms: importCert for key: " + alias + ": Failed");
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }
    }

    public X509Certificate signCSRwithCA(String caAlias, String csrKeyAlias, boolean isRSA) {
        System.out.println("jms: signCSRwithCA, key(" + csrKeyAlias + ") with CA(" + caAlias + ")");
        PKCS10CertificationRequest csr = generateCSR(csrKeyAlias, isRSA);
//        byte[] csrBytes = new byte[0];
//        try {
//            csrBytes = csr.getEncoded();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        PemObject pemObject = new PemObject("CERTIFICATE REQUEST", csrBytes);
//        StringWriter stringWriter = new StringWriter();
//        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
//            pemWriter.writeObject(pemObject);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        String pemStr = stringWriter.toString();
//        FileOutputStream fos = null;
//        String csrFile = "/sdcard/Download/" + csrKeyAlias + ".csr";
//        try {
//            fos = new FileOutputStream(csrFile);
//            fos.write(pemStr.getBytes());
//            fos.close();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//
//        String pemFileContent = ""; // 存储PEM文件内容的字符串
//
//        try {
//            FileReader fileReader = new FileReader(csrFile);
//            BufferedReader bufferedReader = new BufferedReader(fileReader);
//            String line;
//
//            while ((line = bufferedReader.readLine()) != null) {
//                pemFileContent += line + "\n";
//            }
//
//            bufferedReader.close();
//        } catch (IOException e) {
//            // 处理文件读取异常
//            e.printStackTrace();
//        }
//        PKCS10CertificationRequest pkcs10CertificationRequest = getCSRFromString(pemFileContent);

        System.out.println("jms: csr: " + csr.toString());
        X509Certificate certificate = signCSR(caAlias, csr, isRSA);
        System.out.println("jms: signCSR(): Certificate: " + certificate.toString());

        return certificate;
    }

    public PrivateKey createECPrivateKey(String alias) {
        ECKey ecPrivateKey = (ECKey) getPrivateKey(alias);
        return new CustECPrivateKey(alias, TLS_PRI_KEY_FORMAT, ecPrivateKey.getParams());
    }

    public PrivateKey createRSAPrivateKey(String alias) {
        RSAKey rsaKey = (RSAKey) getPrivateKey(alias);
        return new CustRSAPrivateKey(alias, rsaKey.getModulus());
    }

    public X509Certificate signCSR(String alias, PKCS10CertificationRequest csr, boolean isRSA) {
        System.out.println("signCSR(use: " + alias + ")");
        PrivateKey privateKey = getPrivateKey(alias);
        Date startDate = new Date();
        Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000); // 设置证书有效期为1年
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        X500Name subject = csr.getSubject();
        X500Name issuer = new X500Name("C=CN,ST=BJ,L=PEK,O=" + alias);
        X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(
                issuer,
                serialNumber,
                startDate,
                endDate,
                subject,
                csr.getSubjectPublicKeyInfo()
        );
        X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(
                new CustContentSigner(privateKey, isRSA)
        );
        X509Certificate certificate = null;
        try {
            certificate = new JcaX509CertificateConverter().getCertificate(x509CertificateHolder);
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        return certificate;
    }

    public String getDefaultKeyAlias() {
        return KEY_ALIAS;
    }

    public ECCKeyUtil() {
        try {
            mKeyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
            mKeyStore.load(null);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(b & 0xFF);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex.toUpperCase());
        }
        return hexString.toString();
    }

    // ?????
    public static byte[] deriveKey(byte[] salt, byte[] ikm, byte[] info, int length) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(salt, "HmacSHA256");
        hmac.init(keySpec);

        byte[] prk = hmac.doFinal(ikm);
        SecretKeySpec prkSpec = new SecretKeySpec(prk, "HmacSHA256");
        byte[] derivedKey = new byte[length];
        byte[] t = new byte[0];
        int pos = 0;
        while (pos < length) {
            hmac.reset();
            hmac.init(prkSpec);
            hmac.update(t);
            hmac.update(info);
            byte c = (byte) ((pos + 1) & 0xff);
            hmac.update(c);
            t = hmac.doFinal();
            System.arraycopy(t, 0, derivedKey, pos, Math.min(t.length, length - pos));
            pos += t.length;
        }

        return derivedKey;
    }

    public byte[] deriveKeyBC(byte[] salt, byte[] ikm, byte[] info, int len) {
        Digest digest = DigestFactory.createSHA256();
        HKDFBytesGenerator hkdfBytesGenerator = new HKDFBytesGenerator(digest);
        hkdfBytesGenerator.init(new HKDFParameters(ikm, salt, info));
        byte[] okm = new byte[len];
        hkdfBytesGenerator.generateBytes(okm, 0, len);
        return okm;
    }

    public static ECPrivateKeyParameters constructPrivateKeyParameters(byte[] privateKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        int ret = Security.insertProviderAt(new BouncyCastleProvider(), 1);
        BigInteger s = new BigInteger(privateKeyBytes);
        System.out.println("s: " + s.toString(16).toUpperCase());
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        BigInteger n = ecSpec.getN();
        BigInteger subval = n.subtract(BigInteger.ONE);
        BigInteger modval = s.mod(subval);
        BigInteger privateKey = modval.add(BigInteger.ONE);
        if (DEBUG) {
            System.out.println("n: " + n.toString(16).toUpperCase());
            System.out.println("subval: " + subval.toString(16).toUpperCase());
            System.out.println("modval: " + modval.toString(16).toUpperCase());
            System.out.println("privateKey: " + privateKey.toString(16).toUpperCase());
        }
        ECDomainParameters ecDomainParameters = new ECDomainParameters(
                ecSpec.getCurve(),
                ecSpec.getG(),
                ecSpec.getN()
        );
        return new ECPrivateKeyParameters(privateKey, ecDomainParameters);
    }

    public PrivateKey constructPrivateKey(ECPrivateKeyParameters parameters) {
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("EC", "BC");
        } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        PrivateKey ecPrivKey = null;
        try {
            assert keyFactory != null;
            ecPrivKey = keyFactory.generatePrivate(new ECPrivateKeySpec(parameters.getD(), ecSpec));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return ecPrivKey;
    }

    public void showPEM(byte[] input, boolean isPriv) {
        PemObject pemObject = null;
        if (isPriv) {
            pemObject = new PemObject("EC PRIVATE KEY", input);
        } else {
            pemObject = new PemObject("EC PUBLIC KEY", input);
        }
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        try {
            pemWriter.writeObject(pemObject);
            pemWriter.close();
            System.out.println("key: " + stringWriter.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void test() {
        int chip_hardward_id = OEM_ID + JTAG_ID;
        System.out.println("FUSE_ROOT_HASH len: " + FUSE_ROOT_HASH.length());
        byte[] okm = new byte[0];
        PrivateKey eccPrivKey = null;
        ECPrivateKeyParameters ecPrivateKeyParameters = null;
        okm = deriveKeyBC(SALT.getBytes(), APP_SECRET.getBytes(), FUSE_ROOT_HASH.getBytes(), OKM_LEN);
        try {
            ecPrivateKeyParameters = constructPrivateKeyParameters(okm);
            eccPrivKey = constructPrivateKey(ecPrivateKeyParameters);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(eccPrivKey.getEncoded());
        showPEM(eccPrivKey.getEncoded(), true);
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECDomainParameters ecDomainParameters = new ECDomainParameters(
                ecSpec.getCurve(),
                ecSpec.getG(),
                ecSpec.getN()
        );

        ECDHBasicAgreement basicAgreement = new ECDHBasicAgreement();
        basicAgreement.init((CipherParameters) ecPrivateKeyParameters);
        byte[] rdPubEphemeral = new byte[0];
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            rdPubEphemeral = Base64.getDecoder().decode(RD_PUB_EPHEMERAL_PROD);
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(rdPubEphemeral);
            JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter();
                BCECPublicKey ecPublicKey = null;
            try {
                ecPublicKey = (BCECPublicKey) keyConverter.getPublicKey(subjectPublicKeyInfo);
            } catch (PEMException e) {
                e.printStackTrace();
            }
            showPEM(ecPublicKey.getEncoded(),false);
            ECParameterSpec ecParameterSpec = ecPublicKey.getParameters();
            ECDomainParameters domainParameters = new ECDomainParameters(
                    ecParameterSpec.getCurve(),
                    ecParameterSpec.getG(),
                    ecParameterSpec.getN(),
                    ecParameterSpec.getH(),
                    ecParameterSpec.getSeed()
            );

            ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(
                    ecPublicKey.getQ(),
                    domainParameters
            );
            BigInteger secret = basicAgreement.calculateAgreement(publicKeyParameters);
            System.out.println("session_key_base64: " + Base64.getEncoder().encodeToString(secret.toByteArray()));
        }
    }

    public void importPrivateKey(PrivateKey privateKey, Certificate certificate) {
        KeyPair keyPair = new KeyPair(null, privateKey);
        KeyStore.Entry entry = null;
        try {
            entry = mKeyStore.getEntry(PLT_KEY_ALIAS, null);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }
        if (null == entry) {
            System.out.println("Add " + PLT_KEY_ALIAS + " to AndroidKeyStore");
            try {
                mKeyStore.setKeyEntry(PLT_KEY_ALIAS, keyPair.getPrivate(), null, null);
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println(PLT_KEY_ALIAS + " existed");
        }
    }

    public void deleteKey(String alias) {
        System.out.println("jms: deleteKey(" + alias + ")");
        try {
            mKeyStore.deleteEntry(alias);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    public KeyStore.PrivateKeyEntry genKeyPair(String alias, boolean isRSA) {
        System.out.println("jms: genKeyPair(" + alias + "), isRSA: " + isRSA);
        KeyStore.PrivateKeyEntry keyEntry = null;
        try {
            keyEntry = (KeyStore.PrivateKeyEntry) mKeyStore.getEntry(alias, null);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }
        if (null == keyEntry) {
            KeyPairGenerator keyPairGenerator = null;
            try {
                KeyGenParameterSpec.Builder builder = null;
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                    builder = new KeyGenParameterSpec.Builder(
                            alias,
                            KeyProperties.PURPOSE_SIGN |
                                    KeyProperties.PURPOSE_VERIFY |
                                    KeyProperties.PURPOSE_AGREE_KEY |
                                    KeyProperties.PURPOSE_ENCRYPT |
                                    KeyProperties.PURPOSE_DECRYPT
                    )
                    .setSignaturePaddings(
                            KeyProperties.SIGNATURE_PADDING_RSA_PKCS1,
                            KeyProperties.SIGNATURE_PADDING_RSA_PSS
                    );

                    if (isRSA) {
                        keyPairGenerator = KeyPairGenerator.getInstance(
                                KeyProperties.KEY_ALGORITHM_RSA,
                                ANDROID_KEYSTORE_PROVIDER
                        );
                        builder.setKeySize(2048)
                                .setEncryptionPaddings(
                                        KeyProperties.ENCRYPTION_PADDING_NONE,
                                        KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
                                )
                                .setRandomizedEncryptionRequired(false);
                    } else {
                        keyPairGenerator = KeyPairGenerator.getInstance(
                                KeyProperties.KEY_ALGORITHM_EC,
                                ANDROID_KEYSTORE_PROVIDER
                        );
                        builder.setAlgorithmParameterSpec(
                                new ECGenParameterSpec("secp256r1")
                        )
                        .setKeySize(256);
                    }
                    builder.setDigests(
                            KeyProperties.DIGEST_NONE,
                            KeyProperties.DIGEST_SHA1,
                            KeyProperties.DIGEST_SHA256,
                            KeyProperties.DIGEST_SHA384)
                    .setUserAuthenticationRequired(false)
                    .setCertificateSubject(new X500Principal("C=CN, ST=BJ, L=PEK, O=" + alias));
                    keyPairGenerator.initialize(builder.build());
                }
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                try {
                    keyEntry = (KeyStore.PrivateKeyEntry) mKeyStore.getEntry(alias, null);
//                    System.out.println("jms: genKeyPair's Cert: " + Base64.getEncoder().encodeToString(keyEntry.getCertificate().getEncoded()));
                } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
                    e.printStackTrace();
                }
            } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
                e.printStackTrace();
            }
        }
        return keyEntry;
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    public void genKeyPairDefault() {
        try {
            mPrivateKeyEntry = (KeyStore.PrivateKeyEntry) mKeyStore.getEntry(KEY_ALIAS, null);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }
        if (null == mPrivateKeyEntry) {
            KeyPairGenerator keyPairGenerator = null;
            try {
                keyPairGenerator = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_EC,
                        ANDROID_KEYSTORE_PROVIDER
                );
                KeyGenParameterSpec.Builder builder = null;
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                    builder = new KeyGenParameterSpec.Builder(
                            KEY_ALIAS,
                            KeyProperties.PURPOSE_SIGN |
                                    KeyProperties.PURPOSE_VERIFY |
                                    KeyProperties.PURPOSE_AGREE_KEY)
                            .setAlgorithmParameterSpec(
                                    new ECGenParameterSpec("secp256r1")
                            )
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                            .setKeySize(256)
                            .setUserAuthenticationRequired(false);
                    keyPairGenerator.initialize(builder.build());
                }
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                mPrivatekey = keyPair.getPrivate();
                mPublicKey = keyPair.getPublic();
            } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
                e.printStackTrace();
            }
        } else {
            mPrivatekey = mPrivateKeyEntry.getPrivateKey();
            mPublicKey = mPrivateKeyEntry.getCertificate().getPublicKey();
        }
    }

    public X509Certificate getCertificate(String alias) {
        System.out.println("jms: getCertificate(" + alias + ")");
        KeyStore.PrivateKeyEntry privateKeyEntry = null;
        Certificate certificate = null;
        try {
            privateKeyEntry = (KeyStore.PrivateKeyEntry) mKeyStore.getEntry(alias, null);
            certificate = privateKeyEntry.getCertificate();
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }
        return (X509Certificate) certificate;
    }

    public PrivateKey getPrivateKey(String alias) {
        System.out.println("jms: getPrivateKey(" + alias + ")");
        KeyStore.PrivateKeyEntry privateKeyEntry = null;
        try {
            privateKeyEntry = (KeyStore.PrivateKeyEntry) mKeyStore.getEntry(alias, null);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();
        return privateKey;
    }

    public PublicKey getPublicKey(String alias) {
        System.out.println("jms: getPublicKey(" + alias + ")");
        KeyStore.PrivateKeyEntry privateKeyEntry = null;
        try {
            privateKeyEntry = (KeyStore.PrivateKeyEntry) mKeyStore.getEntry(alias, null);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }
        PublicKey publicKey = privateKeyEntry.getCertificate().getPublicKey();
        return  publicKey;
    }

    // Good
    public byte[] sign(String alias, byte[] input) {
        PrivateKey privateKey = getPrivateKey(alias);
        Signature signature = null;
        try {
            signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(privateKey);
            signature.update(input);
            return signature.sign();
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    // Good
    public boolean verify(String alias, byte[] input, byte[] sig) {
        Signature signature = null;
        PublicKey publicKey = getPublicKey(alias);
        try {
            signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(publicKey);
            signature.update(input);
            return signature.verify(sig);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return false;
    }

    public PKCS10CertificationRequest getCSRFromString(String csrPem) {
        PEMParser pemParser = new PEMParser(new StringReader(csrPem));
        Object pemObject = null;
        try {
            pemObject = pemParser.readObject();
            pemParser.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (pemObject instanceof PKCS10CertificationRequest) {
            PKCS10CertificationRequest certificationRequest = (PKCS10CertificationRequest) pemObject;

            return certificationRequest;
        } else {
            return null;
        }
    }

    // Good
    public PKCS10CertificationRequest generateCSR(String alias, boolean isRSA) {
        System.out.println("generateCSR(" + alias + ")");

        X500Name x500Name = new X500Name("C=CN, ST=BJ, L=PEK, O=" + alias);
        PublicKey publicKey = getPublicKey(alias);
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                x500Name,
                publicKey
        );
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        try {
            extensionsGenerator.addExtension(
                    Extension.basicConstraints,
                    true,
                    new BasicConstraints(true)
            );
        } catch (IOException e) {
            e.printStackTrace();
        }
        builder.addAttribute(
                PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                extensionsGenerator.generate()
        );
        PrivateKey privateKey = getPrivateKey(alias);
        return builder.build(
                new CustContentSigner(privateKey, isRSA)
        );
    }

    public byte[] ECDH(String alias, byte[] serverEphemeral) {
        KeyAgreement keyAgreement = null;
        PrivateKey privateKey = getPrivateKey(alias);
        byte[] secret = new byte[0];
        try {
            keyAgreement = KeyAgreement.getInstance(
                    "ECDH",
                    ANDROID_KEYSTORE_PROVIDER
            );
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        try {
            keyAgreement.init(privateKey);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            X509EncodedKeySpec serverKeySpec = new X509EncodedKeySpec(serverEphemeral);
            PublicKey serverEphemeralPublicKey = keyFactory.generatePublic(serverKeySpec);
            Key aesKey = keyAgreement.doPhase(serverEphemeralPublicKey, true);
            secret = keyAgreement.generateSecret();
        } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return secret;
    }

    public byte[] encrypt(byte[] secret, byte[] input, ByteArrayOutputStream ivout) {
        SecretKeySpec aesKeySpec = new SecretKeySpec(secret, "AES");
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKeySpec);
            byte[] encryptedData = cipher.doFinal(input);
            byte[] iv = cipher.getIV();
            ivout.write(iv);
            return encryptedData;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    public byte[] decrypt(byte[] secret, byte[] input, byte[] iv) {
        SecretKeySpec aesKeySpec = new SecretKeySpec(secret, "AES");
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, aesKeySpec, new IvParameterSpec(iv));
            byte[] decryptedData = cipher.doFinal(input);
            System.out.println("decryptedData: " + new String(decryptedData));
            return decryptedData;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

}
