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

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Base64;

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

        if (true) {
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

        if (false) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                mKeyUtil.genKeyPairDefault();
            }
            String clientAlias = CLIENT_KEY_ALIAS;
            String serverEphemeralString = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3JZcof/4ONKBqHyQ0g+2i36Ot0BwXZPMZor0xDguZQL711xfWR6y7TjJ5u3TgdEVn9iSKhrqEf8mrtr5ZpfrUw==";
            byte[] serverEphemeralPublicKey = new byte[0];
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                serverEphemeralPublicKey = Base64.getDecoder().decode(serverEphemeralString);
            }
            String inputStr = "Hello ECC";
            byte[] input = inputStr.getBytes(StandardCharsets.UTF_8);

            // Encrypt Data
            byte[] secret = mKeyUtil.ECDH(clientAlias, serverEphemeralPublicKey);
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