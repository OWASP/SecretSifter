package com.secretsifter;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.net.ssl.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Manages the self-signed CA certificate and per-host server certificates used
 * for HTTPS MITM interception in the built-in proxy.
 *
 * A new CA keypair + certificate is generated each time the proxy starts.
 * The user exports the CA cert from the Proxy tab and installs it in their
 * browser's trust store once per session.
 */
public class CertificateAuthority {

    private final KeyPair           caKeyPair;
    private final X509Certificate   caCert;
    private final AtomicLong        serialCounter = new AtomicLong(System.currentTimeMillis());
    private final Map<String, SSLContext> hostCtxCache = new ConcurrentHashMap<>();

    public CertificateAuthority() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048, new SecureRandom());
        caKeyPair = kpg.generateKeyPair();
        caCert    = buildCaCert();
    }

    /** DER-encoded CA certificate bytes — write to a .crt file for browser import. */
    public byte[] getCaCertDer() throws Exception {
        return caCert.getEncoded();
    }

    /** PEM-formatted CA certificate — for display or copy-paste. */
    public String getCaCertPem() throws Exception {
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(caCert.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
    }

    /**
     * Returns an SSLContext for use as the server-side of a CONNECT tunnel to {@code hostname}.
     * The context presents a certificate signed by our CA.  Results are cached per hostname.
     */
    public SSLContext serverContext(String hostname) throws Exception {
        return hostCtxCache.computeIfAbsent(hostname, h -> {
            try { return buildServerCtx(h); }
            catch (Exception e) { throw new RuntimeException("cert gen failed for " + h, e); }
        });
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    private X509Certificate buildCaCert() throws Exception {
        X500Name  name   = new X500Name("CN=SecretSifter CA,O=SecretSifter,C=US");
        Date      from   = new Date();
        Date      to     = new Date(from.getTime() + 10L * 365 * 86_400_000L);
        BigInteger serial = BigInteger.valueOf(serialCounter.getAndIncrement());

        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                name, serial, from, to, name, caKeyPair.getPublic());
        b.addExtension(Extension.basicConstraints, true,  new BasicConstraints(true));
        b.addExtension(Extension.keyUsage,         true,  new KeyUsage(
                KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(caKeyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(b.build(cs));
    }

    private SSLContext buildServerCtx(String hostname) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048, new SecureRandom());
        KeyPair serverKp = kpg.generateKeyPair();

        X500Name issuer  = new X500Name("CN=SecretSifter CA,O=SecretSifter,C=US");
        X500Name subject = new X500Name("CN=" + hostname);
        Date     from    = new Date();
        Date     to      = new Date(from.getTime() + 365L * 86_400_000L);
        BigInteger serial = BigInteger.valueOf(serialCounter.getAndIncrement());

        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuer, serial, from, to, subject, serverKp.getPublic());
        b.addExtension(Extension.basicConstraints,       false, new BasicConstraints(false));
        b.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, hostname)));

        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(caKeyPair.getPrivate());
        X509Certificate serverCert = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(b.build(cs));

        // Build a KeyStore with the server cert + CA cert chain
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("server", serverKp.getPrivate(), new char[0],
                new java.security.cert.Certificate[]{serverCert, caCert});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        return ctx;
    }
}
