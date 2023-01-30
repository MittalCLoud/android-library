package com.owncloud.android.lib.common.network;

import static android.content.ContentValues.TAG;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.res.AssetManager;
import android.webkit.ClientCertRequest;

import androidx.annotation.NonNull;

import com.owncloud.android.lib.common.utils.Log_OC;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

public class MittalX509KeyManager {
    Context context;
    public MittalX509KeyManager(Context context) throws IOException, KeyStoreException {
        this.context = context;

    }
    KeyStore ks = KeyStore.getInstance("PKCS12");

    AssetManager assetManager = context.getAssets();

    InputStream cert = assetManager.open("mittal-client.p12");
    String password = "mittal";

    private final static String TAG = MittalX509KeyManager.class.getCanonicalName();

    public KeyManager[] mittalKeyManager() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {

        ks.load(cert,password.toCharArray());
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(ks,password.toCharArray());
        return keyManagerFactory.getKeyManagers();
    }
    @TargetApi(21)
    public void handlewebview(@NonNull final ClientCertRequest request) {
        Log_OC.d(TAG, "handleWebViewClientCertRequest(keyTypes=" + Arrays.toString(request.getKeyTypes()) +
                ", issuers=" + Arrays.toString(request.getPrincipals()) + ", hostname=" + request.getHost() +
                ", port=" + request.getPort() + ")");
        new Thread() {
            @Override
            public void run() {

                try {
                    ks.load(cert,password.toCharArray());

                    PrivateKey key = (PrivateKey)ks.getKey("1", password.toCharArray());
                    X509Certificate[] chain = (X509Certificate[]) ks.getCertificateChain("1");
                    Log_OC.d(TAG, "handleWebViewClientCertRequest: proceed, alias = " );
                    request.proceed(key, chain);
                    return;
                } catch (CertificateException e) {
                    throw new RuntimeException(e);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                } catch (UnrecoverableKeyException e) {
                    throw new RuntimeException(e);
                } catch (KeyStoreException e) {
                    throw new RuntimeException(e);
                }


            }
        }.start();
    }
}
