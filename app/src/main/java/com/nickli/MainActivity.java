package com.nickli;

import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;

import androidx.appcompat.app.AppCompatActivity;

import com.nickli.hellokeystore.R;
import com.nickli.security.netty.NettyClient;
import com.nickli.security.netty.NettyServer;
import com.nickli.security.utils.KeyUtil;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;

import javax.crypto.KeyAgreement;

public class MainActivity extends AppCompatActivity {
//    private ECCKeyUtil mECCKeyUtil = new ECCKeyUtil();
    HandlerThread sendThread = new HandlerThread("Sender");
    HandlerThread recvThread = new HandlerThread("Receiver");
    Looper sendLooper = null;
    Looper recvLooper = null;
    Handler sendHandler = null;
    Handler recvHander = null;
    NettyClient nettyClient = new NettyClient();
    NettyServer nettyServer = new NettyServer();
    KeyStore.PrivateKeyEntry mPrivateKeyEntry;

    private KeyUtil mKeyUtil = new KeyUtil();
    private static final String ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String CLIENT_KEY_ALIAS = "client_key_alias";
    private static final String SERVER_KEY_ALIAS = "server_key_alias";
    private final String CA_KEY_ALIAS = "ca_key_alias";
    private final String CA_KEY_ALIAS_RSA = "ca_key_alias_rsa";

    // if serverIsRSA is true
    //      Server: RSA, Client: ECC
    //      Serverr ECC, CLient: RSA
    private final boolean serverIsRSA = true;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

//        Security.addProvider(new BouncyCastleProvider());
//
//        try {
//            Thread.sleep(10000);
//        } catch (InterruptedException e) {
//            e.printStackTrace();
//        }

        if (false) {
            mKeyUtil.deleteKey(CA_KEY_ALIAS);
            mKeyUtil.deleteKey(CA_KEY_ALIAS_RSA);
            mKeyUtil.deleteKey(CLIENT_KEY_ALIAS);
            mKeyUtil.deleteKey(SERVER_KEY_ALIAS);

            X509Certificate clientCert = null;
            X509Certificate serverCert = null;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                mKeyUtil.genKeyPair(CA_KEY_ALIAS_RSA, true);
                mKeyUtil.genKeyPair(CA_KEY_ALIAS, false);
                mKeyUtil.genKeyPair(CLIENT_KEY_ALIAS, !serverIsRSA);
                mKeyUtil.genKeyPair(SERVER_KEY_ALIAS, serverIsRSA);
                if (serverIsRSA) {
                    clientCert = mKeyUtil.signCSRwithCA(CA_KEY_ALIAS, CLIENT_KEY_ALIAS, !serverIsRSA);
                    serverCert= mKeyUtil.signCSRwithCA(CA_KEY_ALIAS_RSA, SERVER_KEY_ALIAS, serverIsRSA);
                } else {
                    clientCert = mKeyUtil.signCSRwithCA(CA_KEY_ALIAS_RSA, CLIENT_KEY_ALIAS, !serverIsRSA);
                    serverCert= mKeyUtil.signCSRwithCA(CA_KEY_ALIAS, SERVER_KEY_ALIAS, serverIsRSA);
                }
            }
            nettyClient.setCertificate(clientCert, !serverIsRSA);
            nettyServer.setCertificate(serverCert, serverIsRSA);

            sendThread.start();
            sendLooper = sendThread.getLooper();
            sendHandler = new Handler(sendLooper);
            sendHandler.post(new Runnable() {
                @Override
                public void run() {
                    try {
                        Thread.sleep(100);
                        System.out.println("jms: nettyClient send");
                        nettyClient.send();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            });

            System.out.println("jms: recvThread start");
            recvThread.start();
            recvLooper = recvThread.getLooper();
            recvHander = new Handler(recvLooper);
            recvHander.post(new Runnable() {
                @Override
                public void run() {
                    try {
                        System.out.println("jms: nettyServer recv");
                        nettyServer.recv();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            });
        }

        if (true) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                mKeyUtil.genKeyPairDefault();
            }
            String clientAlias = CLIENT_KEY_ALIAS;
//            String serverEphemeralString = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3JZcof/4ONKBqHyQ0g+2i36Ot0BwXZPMZor0xDguZQL711xfWR6y7TjJ5u3TgdEVn9iSKhrqEf8mrtr5ZpfrUw==";
//            byte[] serverEphemeralPublicKey = new byte[0];
//            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
//                serverEphemeralPublicKey = Base64.getDecoder().decode(serverEphemeralString);
//            }


            String inputStr = "Hello ECC";
            byte[] input = inputStr.getBytes(StandardCharsets.UTF_8);

            String xPoint = "aec36e41791fabfc2ddd3223a8ef59a658a9e30cd92a5d241bbf4c18684a4a61";
            String yPoint = "c9aa0d1d9d3181d3022d2f64c7663000915622d4e670cce86737bb00cab5de91";
            byte[] xBytes = KeyUtil.hexStringToByteArray(xPoint);
            byte[] yBytes = KeyUtil.hexStringToByteArray(yPoint);
            ECPoint pubPoint = new ECPoint(
                    new BigInteger(1, xBytes),
                    new BigInteger(1, yBytes)
            );
            AlgorithmParameters parameters = null;
            ECPublicKey ecPublicKey = null;
            try {
                parameters = AlgorithmParameters.getInstance("EC");
                parameters.init(new ECGenParameterSpec("prime256v1"));
                java.security.spec.ECParameterSpec parameterSpec =
                        parameters.getParameterSpec(
                            java.security.spec.ECParameterSpec.class
                        );
                ECPublicKeySpec spec = new ECPublicKeySpec(pubPoint, parameterSpec);
                KeyFactory factory = KeyFactory.getInstance("EC");
                ecPublicKey = (ECPublicKey) factory.generatePublic(spec);
            } catch (NoSuchAlgorithmException | InvalidParameterSpecException |
                    InvalidKeySpecException e) {
                e.printStackTrace();
            }
            assert ecPublicKey != null;

            KeyAgreement keyAgreement = null;
            PrivateKey privateKey = mKeyUtil.getPrivateKey(clientAlias);
            byte[] secret = new byte[0];
            try {
                keyAgreement = KeyAgreement.getInstance(
                        "ECDH",
                        ANDROID_KEYSTORE_PROVIDER
                );
                assert keyAgreement != null;
                keyAgreement.init(privateKey);
                keyAgreement.doPhase(ecPublicKey, true);
                secret = keyAgreement.generateSecret();
            } catch (InvalidKeyException | NoSuchAlgorithmException |
                    NoSuchProviderException e) {
                e.printStackTrace();
            }




            ByteArrayOutputStream ivout = new ByteArrayOutputStream();
            byte[] encryptedData = mKeyUtil.encrypt(secret, input, ivout);
            // Sign Encryt Data
            byte[] signature = mKeyUtil.sign(clientAlias, encryptedData);

            // Verify Encrypted Data
            boolean verifyResult = mKeyUtil.verify(clientAlias, encryptedData, signature);
            System.out.println("verifyResult: " + verifyResult);
            // Decrypt Data
            byte[] decryptedData = mKeyUtil.decrypt(secret, encryptedData, ivout.toByteArray());
            System.out.println("Decyrpted data: " + new String(decryptedData));
        }
    }
}