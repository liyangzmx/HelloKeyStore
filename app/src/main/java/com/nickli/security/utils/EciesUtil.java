package com.nickli.security.utils;

/*
  This class requires the dependency
  <dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk18on</artifactId>
  </dependency>
 */

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.math.ec.rfc7748.X448;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class EciesUtil {

    public static final String OID_EC_PUBLICKEY = "1.2.840.10045.2.1";
    public static final String OID_P256 = "1.2.840.10045.3.1.7";
    public static final String OID_P384 = "1.3.132.0.34";
    public static final String OID_P521 = "1.3.132.0.35";
    public static final String OID_X25519 = "1.3.101.110";
    public static final String OID_X448   = "1.3.101.111";

    private static final byte[] iv = Hex.decode("4E494F4E494F4E494F4E494F");

    private static final String sk_p256 =
            "1111111111111111111111111111111111111111111111111111111111111111";
    private static final String cert_p256 =
            "MIIBejCCASegAwIBAgIJKs8NmI1LD493MAoGCCqGSM49BAMCMBMxETAPBgNVBAMM" +
                    "CER1bW15IENBMCAXDTIzMDIyNTIyMDMwMFoYDzIxMjMwMjAxMjIwMzAwWjAVMRMw" +
                    "EQYDVQQDDApwcmltZTI1NnYxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAhfm" +
                    "F/C2RDkoJ4+WmZ5pojpPLBUr321s32bluAKC1O0ZSn3ry5dxLS3aPKhaqHZaVvRf" +
                    "x1hZllLyiXxlMG5XlKNgMF4wHwYDVR0jBBgwFoAUAQEBAQEBAQEBAQEBAQEBAQEB" +
                    "AQEwHQYDVR0OBBYEFDPKa8XpIOa+wqFs4Hpw6CgrzWjRMAwGA1UdEwEB/wQCMAAw" +
                    "DgYDVR0PAQH/BAQDAgM4MAoGCCqGSM49BAMCA0EAadD9red+OJQ0eG0qOhDeyo9F" +
                    "D+EG05XX/sB+oQK0xGjk2Y5sTOJDW26pR1DLPxXrphslICBzZVTDddB1yJQUdA==";

    private static final String sk_p384 =
            "1111111111111111111111111111111111111111111111111111111111111111" +
                    "11111111111111111111111111111111";
    private static final String cert_p384 =
            "MIIBljCCAUOgAwIBAgIJYooDHa2xUa3vMAoGCCqGSM49BAMCMBMxETAPBgNVBAMM" +
                    "CER1bW15IENBMCAXDTIzMDIyNTIyMDMwMFoYDzIxMjMwMjAxMjIwMzAwWjAUMRIw" +
                    "EAYDVQQDDAlzZWNwMzg0cjEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQ4bnZ+pctx" +
                    "bJzWIP9zQhKciSpvzO/mEhQMgL/1npQ0aAGd2hblB5sMHZAB0jpiS23QiNDDgmOU" +
                    "GUeHQD6KfQfl4i9+nAuOgPofr/XSi0u1l7Jn8LhwI8ph/IRUvd79Lg6jYDBeMB8G" +
                    "A1UdIwQYMBaAFAEBAQEBAQEBAQEBAQEBAQEBAQEBMB0GA1UdDgQWBBS6AaCqzMWs" +
                    "b45I6IsjJkE6uHudJTAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIDODAKBggq" +
                    "hkjOPQQDAgNBAHgozLylU1LB0VDcahnQEo61pWUo3WT12mUsG1Lfw88APMa1IlGX" +
                    "OlLCHjppjo6eOsQQoMAglksTeg76zE8Ky2g=";

    private static final String sk_p521 =
            "0111111111111111111111111111111111111111111111111111111111111111" +
                    "1111111111111111111111111111111111111111111111111111111111111111" +
                    "1111";
    private static final String cert_p521 =
            "MIIBvDCCAWmgAwIBAgIJfNL2pfvblD94MAoGCCqGSM49BAMCMBMxETAPBgNVBAMM" +
                    "CER1bW15IENBMCAXDTIzMDIyNTIyMDMwMFoYDzIxMjMwMjAxMjIwMzAwWjAUMRIw" +
                    "EAYDVQQDDAlzZWNwNTIxcjEwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAHxfAER" +
                    "6+Y4cvQKRa7t3sfKiUaqWy55hIfd7EL1ee33xbXXgBmbt86nJAHe+c7UR15TjmG/" +
                    "punNe7+vyORwUab60wFSf3288ux910T3KZgTi9SQeVCuK/eqqDgQ+bCL5q5OAM5g" +
                    "bdh1qEkYfnI1c13yqSVv9mLgls/BknPCCPDz2T7hoaNgMF4wHwYDVR0jBBgwFoAU" +
                    "AQEBAQEBAQEBAQEBAQEBAQEBAQEwHQYDVR0OBBYEFHNiylC2gpLticaA5/teMEIP" +
                    "HBbNMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgM4MAoGCCqGSM49BAMCA0EA" +
                    "hl1Mo0vyl6h9Ed1n/HgBmT67691ycn04mOO/tpoZ+LB10ikK+TvkazDu4p4nZZaT" +
                    "Rur5vTUWGCx4+BBOkvMPMQ==";

    private static final String sk_x25519 =
            "1011111111111111111111111111111111111111111111111111111111111151";
    private static final String cert_x25519 =
            "MIIBRDCB8qADAgECAglxsTlvlMA001QwCgYIKoZIzj0EAwIwEzERMA8GA1UEAwwI" +
                    "RHVtbXkgQ0EwIBcNMjMwMjI1MjIwMzAwWhgPMjEyMzAyMDEyMjAzMDBaMA8xDTAL" +
                    "BgNVBAMMBG51bGwwKjAFBgMrZW4DIQB7TpCbvn/+RMRloiADfWCO41iX0x75cvB/" +
                    "dIkssPc/E6NgMF4wHwYDVR0jBBgwFoAUAQEBAQEBAQEBAQEBAQEBAQEBAQEwHQYD" +
                    "VR0OBBYEFBq+0JY1fXF4sdNXf7GXVuFc8Be/MAwGA1UdEwEB/wQCMAAwDgYDVR0P" +
                    "AQH/BAQDAgM4MAoGCCqGSM49BAMCA0EAPxqEAODNKcIhMEJyA4Uw7cV8anmKNRq6" +
                    "qZE+k5ljPb9eh7Y5UlKjcET4G9R5JHvhonTiVYxqZAXz4tMtIns8vg==";

    private static final String sk_x448 =
            "1011111111111111111111111111111111111111111111111111111111111111" +
                    "111111111111111111111111111111111111111111111191";
    private static final String cert_x448 =
            "MIIBXTCCAQqgAwIBAgIJEqY1nQQhqPo5MAoGCCqGSM49BAMCMBMxETAPBgNVBAMM" +
                    "CER1bW15IENBMCAXDTIzMDIyNTIyMDMwMFoYDzIxMjMwMjAxMjIwMzAwWjAPMQ0w" +
                    "CwYDVQQDDARudWxsMEIwBQYDK2VvAzkAsaDDgXDplPEbt/KybSuS8I0vdwV40Dgl" +
                    "MtWKXCiEpJfCd55cfXVJ1nCk8tIomnOjxDTj6lQrZ8ujYDBeMB8GA1UdIwQYMBaA" +
                    "FAEBAQEBAQEBAQEBAQEBAQEBAQEBMB0GA1UdDgQWBBQU/awgHe7JKmUL34sFo2YX" +
                    "CiTQqDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIDODAKBggqhkjOPQQDAgNB" +
                    "AGKr9uZMOjDts9dBAeIw8q5R4OvjWH/4QOwnZq0YlNdwdIBG4PN41QdWTCKUZItq" +
                    "SkGod/fJuUtL0BsNgb+H7d0=";

    private static Map<String, byte[]> curveSkMap = new HashMap<>();
    private static Map<String, byte[]> curveCertMap = new HashMap<>();

    static {
        curveSkMap.put(OID_P256,   Hex.decode(sk_p256));
        curveSkMap.put(OID_P384,   Hex.decode(sk_p384));
        curveSkMap.put(OID_P521,   Hex.decode(sk_p521));
        curveSkMap.put(OID_X25519, Hex.decode(sk_x25519));
        curveSkMap.put(OID_X448,   Hex.decode(sk_x448));

        curveCertMap.put(OID_P256,   Base64.decode(cert_p256));
        curveCertMap.put(OID_P384,   Base64.decode(cert_p384));
        curveCertMap.put(OID_P521,   Base64.decode(cert_p521));
        curveCertMap.put(OID_X25519, Base64.decode(cert_x25519));
        curveCertMap.put(OID_X448,   Base64.decode(cert_x448));
    }

    public static class EciesReceiver {
        private byte[] sk;
        private final byte[] pkIdentifier;
        private final String curveOid;
        private final Set<Byte> allowedCipherSuites = new HashSet<>(3);

        public EciesReceiver(byte[] sk, byte[] certBytes) {
            this.sk = sk;

            Certificate cert = Certificate.getInstance(certBytes);
            byte[] extnValue = cert.getTBSCertificate().getExtensions().getExtension(
                    Extension.subjectKeyIdentifier).getExtnValue().getOctets();
            if (extnValue == null) {
                throw new IllegalArgumentException(
                        "peerCertificate does not extension SubjectKeyIdentifier");
            }

            if (extnValue[0] != 4 || (0xff & extnValue[1]) != extnValue.length - 2) {
                throw new IllegalArgumentException(
                        "Extension SubjectKeyIdentifier does not have correct content");
            } else {
                pkIdentifier = Arrays.copyOfRange(extnValue, 2, extnValue.length);
            }

            SubjectPublicKeyInfo peerSpki = cert.getSubjectPublicKeyInfo();
            String algOid = peerSpki.getAlgorithm().getAlgorithm().getId();

            if (OID_EC_PUBLICKEY.equals(algOid)) {
                this.curveOid = ASN1ObjectIdentifier.getInstance(
                        peerSpki.getAlgorithm().getParameters()).getId();
                if (OID_P256.equals(curveOid)) {
                    allowedCipherSuites.add((byte) 1);
                    allowedCipherSuites.add((byte) 2);
                } else if (OID_P384.equals(curveOid)) {
                    allowedCipherSuites.add((byte) 3);
                    allowedCipherSuites.add((byte) 4);
                } else if (OID_P521.equals(curveOid)) {
                    allowedCipherSuites.add((byte) 5);
                    allowedCipherSuites.add((byte) 6);
                } else {
                    throw new RuntimeException("Unknown curve OID " + curveOid);
                }
            } else if (OID_X25519.equals(algOid) || OID_X448.equals(algOid)) {
                this.curveOid = algOid;
                if (OID_X25519.equals(algOid)) {
                    allowedCipherSuites.add((byte) 7);
                    allowedCipherSuites.add((byte) 8);
                } else {
                    allowedCipherSuites.add((byte) 9);
                    allowedCipherSuites.add((byte) 10);
                }
            } else {
                throw new RuntimeException("Unknown algorithm OID " + algOid);
            }
        }

        public byte[] decrypt(byte[] encryptedData) throws GeneralSecurityException {
            if (encryptedData.length < 2) {
                throw new IllegalArgumentException("encryptedData too short");
            }
            if (encryptedData[0] != 0) {
                throw new IllegalArgumentException("invalid version " + (0xff & encryptedData[0]));
            }

            byte cipherSuite = encryptedData[1];
            if (!allowedCipherSuites.contains(cipherSuite)) {
                throw new IllegalArgumentException("unsupported cipher suite " + (0xff & cipherSuite));
            }

            // get the pkIdentifier
            byte[] pkIdentifier = Arrays.copyOfRange(encryptedData, 2, 22);
            if (!Arrays.equals(this.pkIdentifier, pkIdentifier)) {
                throw new IllegalArgumentException("pkIdentifier in the encrypted data " +
                        "is different from my identifier");
            }

            boolean useAesGcm = cipherSuite == 1 || cipherSuite == 3 || cipherSuite == 5
                    || cipherSuite == 7 || cipherSuite == 9;

            int pkSize = cipherSuite == 1 || cipherSuite == 2 ? 65
                    : cipherSuite == 3 || cipherSuite == 4 ? 97
                    : cipherSuite == 5 || cipherSuite == 6 ? 133
                    : cipherSuite == 7 || cipherSuite == 8 ? 32
                    : 56;
            if (encryptedData.length <= 2 + 20 + pkSize + 16) {
                throw new IllegalArgumentException("encryptedData too short");
            }

            int prefixLen = 2 + 20 + pkSize;
            byte[] tpk = Arrays.copyOfRange(encryptedData, 22, prefixLen);
            byte[] aad = Arrays.copyOfRange(encryptedData, 0, prefixLen);
            byte[] cTag = Arrays.copyOfRange(encryptedData, prefixLen, encryptedData.length);
            byte[] x;

            if (OID_X25519.equals(curveOid) || OID_X448.equals(curveOid)) {
                boolean x25519 = OID_X25519.equals(curveOid);
                int fieldSize = pkSize;

                x = new byte[fieldSize];
                if (x25519) {
                    X25519.scalarMult(sk, 0, tpk, 0, x, 0);
                } else {
                    X448.scalarMult(sk, 0, tpk, 0, x, 0);
                }
            } else {
                int fieldSize = pkSize / 2;
                X9ECParameters parameters = ECNamedCurveTable.getByOID(new ASN1ObjectIdentifier(curveOid));
                ECPoint ecdh = parameters.getCurve().decodePoint(tpk).multiply(
                        new BigInteger(1, sk)).normalize();
                x = Arrays.copyOfRange(ecdh.getEncoded(false), 1, 1 + fieldSize);
            }

            printHex("x(R)", x);
            byte[] k = x2k(x);
            printHex("k(R)", k);

            printHex("iv(R)", iv);
            printHex("aad(R)", aad);
            printHex("c(R)", Arrays.copyOfRange(cTag, 0, cTag.length - 16));
            printHex("tag(R)", Arrays.copyOfRange(cTag, cTag.length - 16, cTag.length));
            Cipher cipher = initCipher(false, useAesGcm, k, iv.clone(), aad);

            byte[] m = cipher.doFinal(cTag);
            printHex("m(R)", m);
            return m;
        }
    }

    public static class EciesSender {
        private final byte[] pkIdentifier;
        private final byte[] encodedPk;
        private final String curveOid;

        private final SecureRandom rnd;

        public EciesSender(byte[] peerCertificate) {
            this(peerCertificate, null);
        }

        public EciesSender(byte[] peerCertificate, SecureRandom rnd) {
            this.rnd = (rnd == null) ? new SecureRandom() : rnd;
            Certificate cert = Certificate.getInstance(peerCertificate);
            byte[] extnValue = cert.getTBSCertificate().getExtensions().getExtension(
                    Extension.subjectKeyIdentifier).getExtnValue().getOctets();
            if (extnValue == null) {
                throw new IllegalArgumentException(
                        "peerCertificate does not extension SubjectKeyIdentifier");
            }

            if (extnValue[0] != 4 || (0xff & extnValue[1]) != extnValue.length - 2) {
                throw new IllegalArgumentException(
                        "Extension SubjectKeyIdentifier does not have correct content");
            } else {
                pkIdentifier = Arrays.copyOfRange(extnValue, 2, extnValue.length);
            }

            SubjectPublicKeyInfo peerSpki = cert.getSubjectPublicKeyInfo();
            String algOid = peerSpki.getAlgorithm().getAlgorithm().getId();

            if (OID_EC_PUBLICKEY.equals(algOid)) {
                this.curveOid = ASN1ObjectIdentifier.getInstance(
                        peerSpki.getAlgorithm().getParameters()).getId();
                if (!(OID_P256.equals(curveOid) || OID_P384.equals(curveOid) || OID_P521.equals(curveOid))) {
                    throw new RuntimeException("Unknown curve OID " + curveOid);
                }
            } else if (OID_X25519.equals(algOid) || OID_X448.equals(algOid)) {
                this.curveOid = algOid;
            } else {
                throw new RuntimeException("Unknown algorithm OID " + algOid);
            }

            this.encodedPk = peerSpki.getPublicKeyData().getOctets();
        }

        public byte[] encrypt(boolean useAesGcm, byte[] m) throws Exception {
            return encrypt(useAesGcm, m, null);
        }

        public byte[] encrypt(boolean useAesGcm, byte[] m, SecureRandom random) throws Exception {
            if (random == null) {
                random = this.rnd;
            }

            byte[] tpk;
            byte[] x;
            int cipherSuite;

            if (OID_X25519.equals(curveOid) || OID_X448.equals(curveOid)) {
                boolean x25519 = OID_X25519.equals(curveOid);
                int fieldSize = x25519 ? 32 : 56;
                if (x25519) {
                    cipherSuite = useAesGcm ? 7 : 8;
                } else {
                    cipherSuite = useAesGcm ? 9 : 10;
                }

                int pkSize = fieldSize;

                // Generate (tsk, tpk)
                byte[] tsk = new byte[fieldSize];
                tpk = new byte[pkSize];
                if (x25519) {
                    X25519.generatePrivateKey(random, tsk);
                    X25519.generatePublicKey(tsk, 0, tpk, 0);
                } else {
                    X448.generatePrivateKey(random, tsk);
                    X448.generatePublicKey(tsk, 0, tpk, 0);
                }
                printHex("tsk(S)", tsk);

                x = new byte[fieldSize];
                if (x25519) {
                    X25519.scalarMult(tsk, 0, encodedPk, 0, x, 0);
                } else {
                    X448.scalarMult(tsk, 0, encodedPk, 0, x, 0);
                }
            } else {
                int fieldSize;
                if (OID_P256.equals(curveOid)) {
                    fieldSize = 32;
                    cipherSuite = useAesGcm ? 1 : 2;
                } else if (OID_P384.equals(curveOid)) {
                    fieldSize = 48;
                    cipherSuite = useAesGcm ? 3 : 4;
                } else {
                    fieldSize = 66;
                    cipherSuite = useAesGcm ? 5 : 6;
                }

                X9ECParameters parameters = ECNamedCurveTable.getByOID(new ASN1ObjectIdentifier(curveOid));
                ECPoint basePoint = parameters.getG();
                BigInteger order = parameters.getCurve().getOrder();

                ECPoint pk = parameters.getCurve().decodePoint(encodedPk);

                BigInteger tsk = new BigInteger(1, randomSk(order, random));
                ECPoint tpkPoint = basePoint.multiply(tsk);

                tpk = tpkPoint.getEncoded(false);
                printHex("tsk(S)", BigIntegers.asUnsignedByteArray(fieldSize, tsk));

                ECPoint ecdh = pk.multiply(tsk).normalize();
                x = Arrays.copyOfRange(ecdh.getEncoded(false), 1, 1 + fieldSize);
            }

            printHex("tpk(S)", tpk);
            printHex("x(S)", x);
            byte[] k = x2k(x);
            printHex("k(S)", k);

            byte[] prefix = new byte[1 + 1 + 20 + tpk.length];
            prefix[0] = 0x00;
            prefix[1] = (byte) cipherSuite;
            System.arraycopy(pkIdentifier, 0, prefix, 2, 20);
            System.arraycopy(tpk, 0, prefix, 22, tpk.length);

            byte[] aad = prefix;

            printHex("m(S)", m);
            printHex("iv(S)", iv);
            printHex("aad(S)", aad);
            Cipher cipher = initCipher(true, useAesGcm, k, iv.clone(), aad);
            byte[] cTag = cipher.doFinal(m);
            printHex("c(S)", Arrays.copyOfRange(cTag, 0, cTag.length - 16));
            printHex("tag(S)", Arrays.copyOfRange(cTag, cTag.length - 16, cTag.length));

            byte[] eciesResult = new byte[prefix.length + cTag.length];
            System.arraycopy(prefix, 0, eciesResult, 0, prefix.length);
            System.arraycopy(cTag, 0, eciesResult, prefix.length, cTag.length);
            return eciesResult;
        }

        private static byte[] randomSk(BigInteger order, SecureRandom rnd) {
            int orderBitLength = order.bitLength();
            BigInteger sk;
            do {
                sk = new BigInteger(orderBitLength, rnd).mod(order);
            } while(!(sk.compareTo(BigInteger.ZERO) > 0 && sk.compareTo(order) < 0));

            return BigIntegers.asUnsignedByteArray((orderBitLength + 7) / 8, sk);
        }
    }

    public void main() {
        try {
            String[] curveOids = {OID_P256, OID_P384, OID_P521, OID_X25519, OID_X448};
            // Test Vector, using tsk from testvector 1
            SecureRandom testVectorRnd = new SecureRandom() {
                @Override
                public void nextBytes(byte[] bytes) {
                    Arrays.fill(bytes, (byte) 0xee);
                }
            };

            for (String curveOid : curveOids) {
                //ecies(curveOid, true, testVectorRnd);
                ecies(curveOid, false, testVectorRnd);
            }

            // random tsk
            for (String curveOid : curveOids) {
                ecies(curveOid, true, null);
                ecies(curveOid, false, null);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private static void ecies(String curveId, boolean useAesGcm, SecureRandom rnd) throws Exception {
        String name = "ECIES Curve " + curveId + " with "
                + (useAesGcm ? "AES-GCM" : "ChaCha20-Poly1305");
        System.out.println(">>> " + name);
        byte[] certBytes = curveCertMap.get(curveId);

        EciesSender sender = new EciesSender(certBytes, rnd);
        EciesReceiver receiver = new EciesReceiver(curveSkMap.get(curveId), certBytes);

        byte[] m = new byte[32];
        Arrays.fill(m, (byte) 0xaa);

        byte[] eciesResult = sender.encrypt(useAesGcm, m);
        printHex("res", eciesResult);

        byte[] m_ = receiver.decrypt(eciesResult);
        if (!Arrays.equals(m, m_)) {
            throw new Exception("decryption failed");
        }

        System.out.println("<<< " + name);
    }

    private static Cipher initCipher(boolean encrypt, boolean useAesGcm,
                                     byte[] key, byte[] iv, byte[] aad)
            throws GeneralSecurityException {
        if (key.length != 32) {
            throw new IllegalArgumentException("Key length must be 256 bits");
        }

        Cipher cipher;
        if (useAesGcm) {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, iv));
        } else {
            cipher = Cipher.getInstance("CHACHA20-POLY1305");
            cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "CHACHA20"),
                    new IvParameterSpec(iv));
        }

        if (aad != null && aad.length != 0) {
            cipher.updateAAD(aad);
        }

        return cipher;
    }

    private static void printHex(String name, byte[] value) {
        String prefix = fixLengthText(name + " (" + value.length + "): ");
        char[] prefixSpaces = new char[prefix.length()];
        java.util.Arrays.fill(prefixSpaces, ' ');

        StringBuilder sb = new StringBuilder();

        String hex = Hex.toHexString(value);
        for (int i = 0; i < hex.length(); i += 64) {
            if (i == 0) {
                sb.append(prefix);
            } else {
                sb.append(prefixSpaces);
            }
            sb.append(hex, i, i + Math.min(64, hex.length() - i)).append("\n");
        }
        sb.deleteCharAt(sb.length() - 1);

        System.out.println(sb);
    }

    private static String fixLengthText(String text) {
        final int len = 15;
        if (text.length() >= len) {
            return text;
        }

        char[] prefix = new char[len - text.length()];
        Arrays.fill(prefix, ' ');
        return new String(prefix) + text;
    }

    private static byte[] x2k(byte[] x) {
        if (x.length == 32) {
            return  x;
        } else if (x.length > 32) {
            return Arrays.copyOfRange(x, x.length - 32, x.length);
        } else {
            throw new IllegalArgumentException("x too short");
        }
    }

}
