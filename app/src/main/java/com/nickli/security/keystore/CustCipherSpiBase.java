package com.nickli.security.keystore;

import com.nickli.security.utils.KeyUtil;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public abstract class CustCipherSpiBase extends CipherSpi {
    private CustRSAPrivateKey mKey;
    private byte[] mInput;
    private int mOpMode;
    private Cipher mCipher;
    private KeyUtil mKeyUtil = new KeyUtil();
    private final String DEFUALT_PROVIDER = "AndroidKeyStoreBCWorkaround";

    protected abstract String getAlgothrim();

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        throw new UnsupportedOperationException("Stub!");
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        throw new UnsupportedOperationException("Stub!");
    }

    @Override
    protected int engineGetBlockSize() {
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return 0;
    }

    @Override
    protected byte[] engineGetIV() {
        return new byte[0];
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    private void resetAll() {
        mInput = null;
        mKey = null;
        mOpMode = 0;
        mCipher = null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        mOpMode = opmode;
        mCipher = null;
        if (key instanceof CustRSAPrivateKey) {
            try {
                mCipher = Cipher.getInstance(getAlgothrim(), DEFUALT_PROVIDER);
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                throw new InvalidKeyException(e);
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            }
            mKey = (CustRSAPrivateKey) key;
            Key cipherKey = null;
            System.out.println("jms: engineInit(" + mKey.getAlias() + ", op: " + opmode + ")");
            if (opmode == Cipher.ENCRYPT_MODE)
                cipherKey = mKeyUtil.getPrivateKey(mKey.getAlias());
            mCipher.init(opmode, cipherKey);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException, InvalidKeyException {

    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidAlgorithmParameterException, InvalidKeyException {

    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if (inputOffset < 0) {
            return new byte[0];
        }

        if (inputLen < 1 || inputOffset + inputLen > input.length) {
            return new byte[0];
        }

        System.out.println("jms: engineUpdate(" + mKey.getAlias() + ", input len: " + input.length + ")");
        mInput = new byte[inputLen];
        try {
            System.arraycopy(input, inputOffset, mInput, 0, inputLen);
        } catch (Exception e) {
            return new byte[0];
        }
        mCipher.update(mInput);
        return new byte[0];
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws BadPaddingException, IllegalBlockSizeException {
        System.out.println("jms: engineDoFinal(" + mKey.getAlias() + ", input len: " + input.length + ", off: " + inputOffset + ")");
        // Then, will change call CDC API to generate encrypted data
        // this demo call Cipher for AndroidKeyStore instead
        return mCipher.doFinal(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws BadPaddingException, IllegalBlockSizeException, ShortBufferException {
        return 0;
    }
}
