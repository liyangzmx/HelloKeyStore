package com.nickli.security.netty;

import android.util.Log;

import com.nickli.security.keystore.CustProvider;
import com.nickli.security.utils.KeyUtil;

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
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.CharsetUtil;

public class NettyServer {
    private static final int PORT = 8888;
    private static final String ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore";

    private KeyStore mKeyStore;
    private KeyStore.PrivateKeyEntry mServerKeyEntry;
    private static final String CLIENT_KEY_ALIAS = "client_key_alias";
    private static final String SERVER_KEY_ALIAS = "server_key_alias";
    private final String CA_KEY_ALIAS = "ca_key_alias";
    private final String CA_KEY_ALIAS_RSA = "ca_key_alias_rsa";
    private KeyUtil mKeyUtil = new KeyUtil();

    private boolean mIsRSA = false;

    public void setCertificate(X509Certificate certificate, boolean isRSA) {
        this.certificate = certificate;
        this.mIsRSA = isRSA;
    }

    private X509Certificate certificate;

    public void recv() throws InterruptedException {
        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup workerGroup = new NioEventLoopGroup();

        try {
            mKeyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
            mKeyStore.load(null);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            mServerKeyEntry = (KeyStore.PrivateKeyEntry) mKeyStore.getEntry(SERVER_KEY_ALIAS, null);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }

        try {
            ServerBootstrap bootstrap = new ServerBootstrap();
            bootstrap.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            ChannelPipeline pipeline = ch.pipeline();
                            X509KeyManager[] x509KeyManagers = new X509KeyManager[1];
                            x509KeyManagers[0] = new X509KeyManager() {
                                @Override
                                public String[] getClientAliases(String keyType, Principal[] issuers) {
                                    System.out.println("jms: server getClientAliases, keyType: " + keyType);
                                    return new String[0];
                                }

                                @Override
                                public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
                                    System.out.println("jms: server chooseClientAlias, keyType: " + keyType);
                                    return null;
                                }

                                @Override
                                public String[] getServerAliases(String keyType, Principal[] issuers) {
                                    System.out.println("jms: server getServerAliases, keyType: " + keyType);
                                    return new String[0];
                                }

                                @Override
                                public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
                                    if ("RSA" == keyType) {
                                        System.out.println("jms: server chooseServerAlias, keyType: " + keyType + ", Skip still EC");
                                        return null;
                                    }
                                    System.out.println("jms: server chooseServerAlias, keyType: " + keyType);
                                    return SERVER_KEY_ALIAS;
                                }

                                @Override
                                public X509Certificate[] getCertificateChain(String alias) {
                                    System.out.println("jms: server getCertificateChain, alias: " + alias);
//            return new X509Certificate[] {(X509Certificate) mServerKeyEntry.getCertificate()};
//                                    return new X509Certificate[]{ mECCKeyUtil.getCertificate(alias) };
                                    return new X509Certificate[] {certificate};
                                }

                                @Override
                                public PrivateKey getPrivateKey(String alias) {
                                    System.out.println("jms: server getPrivateKey, alias: " + alias);
                                    if ( true ) {
                                        CustProvider.installAsDefault();
                                        if (mIsRSA)
                                            return mKeyUtil.createRSAPrivateKey(alias);
                                        else
                                            return mKeyUtil.createECPrivateKey(alias);
                                    } else {
                                        return mKeyUtil.getPrivateKey(alias);
                                    }
                                }
                            };
                            X509TrustManager[] x509TrustManagers = new X509TrustManager[1];
                            x509TrustManagers[0] = new X509TrustManager() {
                                @Override
                                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                                    System.out.println("jms: client checkClientTrusted, authType: " + authType);

                                    if (chain == null || chain.length == 0) {
                                        throw new CertificateException("certificate chain is null.");
                                    }

                                    X509Certificate cert = chain[0];
//                                    System.out.println("jms: Peer Cert: " + cert.toString());

                                    X509Certificate caCert = null;
                                    if (!mIsRSA)
                                        caCert = (X509Certificate) mKeyUtil.getCertificate(CA_KEY_ALIAS_RSA);
                                    else
                                        caCert = (X509Certificate) mKeyUtil.getCertificate(CA_KEY_ALIAS);
//                                    System.out.println("jms: server: Our CA: " + caCert.toString());//                                    System.out.println("jms: Our CA: " + caCert.toString());
                                    try {
                                        cert.verify(caCert.getPublicKey(), "AndroidKeyStoreBCWorkaround");
                                        System.out.println("jms: server checkClientTrusted cert success.");
                                        return;
                                    } catch (CertificateException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
                                        throw new CertificateException("cert verify failed, " + e);
                                    }
                                }

                                @Override
                                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                                    System.out.println("jms: server checkServerTrusted, authType: " + authType);
                                }

                                @Override
                                public X509Certificate[] getAcceptedIssuers() {
                                    System.out.println("jms: server getAcceptedIssuers");
//                                    return new X509Certificate[] { (X509Certificate) mServerKeyEntry.getCertificate()};
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
                            sslEngine.setUseClientMode(false);
                            sslEngine.setNeedClientAuth(true);
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
                                    Log.d("jms", "jms: Server Received message: " + receivedMessage);
                                    String responseMessage = "Hello from server";
                                    ctx.writeAndFlush(responseMessage);
                                }
                            });
                        }
                    });

            ChannelFuture future = bootstrap.bind(PORT).sync();
            Log.d("jms", "jms: Server started on port " + PORT);

            future.channel().closeFuture().sync();
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }
}