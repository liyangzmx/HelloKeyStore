package com.nickli.security.netty;

import android.security.keystore.KeyProperties;
import android.util.Log;

import com.nickli.security.keystore.CustProvider;
import com.nickli.security.utils.ECCKeyUtil;

import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.CharsetUtil;

public class NettyClient {
    private static final String HOST = "localhost";
    private static final int PORT = 8888;
    private static final String CLIENT_KEY_ALIAS = "client_key_alias";
    private static final String SERVER_KEY_ALIAS = "server_key_alias";
    private static final String ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore";
    private final String CA_KEY_ALIAS = "ca_key_alias";

    private KeyStore mKeyStore;
    private KeyStore.PrivateKeyEntry mCientKeyEntry;
    private byte[] mSharedSecret = new byte[0];
    private ECCKeyUtil mECCKeyUtil = new ECCKeyUtil();
    private X509Certificate certificate;

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public void send() throws InterruptedException {
        System.out.println("jms: send");
        EventLoopGroup group = new NioEventLoopGroup();
        try {
            mKeyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
            mKeyStore.load(null);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            mCientKeyEntry = (KeyStore.PrivateKeyEntry) mKeyStore.getEntry(CLIENT_KEY_ALIAS, null);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }
        try {
            Bootstrap bootstrap = new Bootstrap();
            bootstrap.group(group)
                    .channel(NioSocketChannel.class)
                    .handler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            ChannelPipeline pipeline = ch.pipeline();
                            X509KeyManager[] x509KeyManagers = new X509KeyManager[1];
                            x509KeyManagers[0] = new X509KeyManager() {
                                @Override
                                public String[] getClientAliases(String keyType, Principal[] issuers) {
                                    System.out.println("jms: client getClientAliases, keyType: " + keyType);
                                    return new String[0];
                                }

                                @Override
                                public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
//                                    for (String kt : keyType)
//                                        System.out.println("jms: client chooseClientAlias, keyType: " + kt);
                                    System.out.println("jms: client chooseClientAlias, ret cust key directly");
//                                    if (keyType[0] == "EC") return null;
                                    return CLIENT_KEY_ALIAS;
                                }

                                @Override
                                public String[] getServerAliases(String keyType, Principal[] issuers) {
                                    System.out.println("jms: client getServerAliases, keyType: " + keyType);
                                    return new String[0];
                                }

                                @Override
                                public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
                                    return null;
                                }

                                @Override
                                public X509Certificate[] getCertificateChain(String alias) {
                                    System.out.println("jms: client getCertificateChain, alias: " + alias);
                                    X509Certificate x509Certificate = mECCKeyUtil.getCertificate(alias);
//                                    return new X509Certificate[] {(X509Certificate) mCientKeyEntry.getCertificate()};
//                                    return new X509Certificate[]{ x509Certificate };
                                    return new X509Certificate[] { certificate };
                                }

                                @Override
                                public PrivateKey getPrivateKey(String alias) {
                                    System.out.println("jms: client getPrivateKey, alias: " + alias);
                                    if ( true ) {
                                        CustProvider.installAsDefault();
                                        return mECCKeyUtil.createRSAPrivateKey(alias);
                                    } else {
                                        return mECCKeyUtil.getPrivateKey(alias);
                                    }
                                }
                            };
                            X509TrustManager[] x509TrustManagers = new X509TrustManager[1];
                            x509TrustManagers[0] = new X509TrustManager() {
                                @Override
                                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                                    System.out.println("jms: checkClientTrusted, authType: " + authType);
                                }

                                @Override
                                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                                    System.out.println("jms: client checkServerTrusted, authType: " + authType);
                                    if (chain == null || chain.length == 0) {
                                        throw new CertificateException("certificate chain is null.");
                                    }

                                    X509Certificate cert = chain[0];
//                                    System.out.println("jms: client: the server Cert: " + cert.toString());

                                    X509Certificate caCert = (X509Certificate) mECCKeyUtil.getCertificate(CA_KEY_ALIAS);
//                                    System.out.println("jms: client: the server CA: " + caCert.toString());
                                    try {
                                        cert.verify(caCert.getPublicKey(), "AndroidKeyStoreBCWorkaround");
                                        System.out.println("jms: client checkServerTrusted cert success.");
                                        return;
                                    } catch (CertificateException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
                                        throw new CertificateException("cert verify failed, " + e);
                                    }
                                }

                                @Override
                                public X509Certificate[] getAcceptedIssuers() {
                                    return new X509Certificate[0];
                                }
                            };
                            SSLContext sslContext = null;
                            try {
                                sslContext = SSLContext.getInstance("TLS");
                                sslContext.init(
                                        x509KeyManagers,
                                        x509TrustManagers,
                                        null
                                );
                            } catch (KeyManagementException | NoSuchAlgorithmException e) {
                                e.printStackTrace();
                            }
                            SSLEngine sslEngine = sslContext.createSSLEngine();
                            sslEngine.setUseClientMode(true);
                            SslHandler sslHandler = new SslHandler(sslEngine);
                            pipeline.addFirst(sslHandler);
                            pipeline.addLast(new StringEncoder(CharsetUtil.UTF_8));
                            pipeline.addLast(new StringDecoder(CharsetUtil.UTF_8));
                            pipeline.addLast(new ChannelInboundHandlerAdapter() {
                                @Override
                                public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                                    super.exceptionCaught(ctx, cause);
                                }

                                @Override
                                public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                                    String receivedMessage = (String) msg;
                                    Log.d("jms", "jms: Client Received message: " + receivedMessage);
                                }
                            });
                        }
                    });

            ChannelFuture future = bootstrap.connect(HOST, PORT).sync();
            Log.d("jms", "jms: Connected to server: " + HOST + ":" + PORT);
            String message = "Hello from client";
            future.channel().writeAndFlush(message).sync();

            future.channel().closeFuture().sync();
        } finally {
            group.shutdownGracefully();
        }
    }
}
