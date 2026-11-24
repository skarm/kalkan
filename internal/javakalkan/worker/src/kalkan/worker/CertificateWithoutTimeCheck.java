package kalkan.worker;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

/** Preserves every certificate property while disabling only validity-period checks. */
final class CertificateWithoutTimeCheck extends X509Certificate {
    private final X509Certificate delegate;

    CertificateWithoutTimeCheck(X509Certificate delegate) {
        this.delegate = delegate;
    }

    X509Certificate unwrap() {
        return delegate;
    }

    @Override
    public void checkValidity() {}

    @Override
    public void checkValidity(Date date) {}

    @Override
    public int getVersion() {
        return delegate.getVersion();
    }

    @Override
    public BigInteger getSerialNumber() {
        return delegate.getSerialNumber();
    }

    @Override
    public Principal getIssuerDN() {
        return delegate.getIssuerDN();
    }

    @Override
    public Principal getSubjectDN() {
        return delegate.getSubjectDN();
    }

    @Override
    public X500Principal getIssuerX500Principal() {
        return delegate.getIssuerX500Principal();
    }

    @Override
    public X500Principal getSubjectX500Principal() {
        return delegate.getSubjectX500Principal();
    }

    @Override
    public Date getNotBefore() {
        return delegate.getNotBefore();
    }

    @Override
    public Date getNotAfter() {
        return delegate.getNotAfter();
    }

    @Override
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        return delegate.getTBSCertificate();
    }

    @Override
    public byte[] getSignature() {
        return delegate.getSignature();
    }

    @Override
    public String getSigAlgName() {
        return delegate.getSigAlgName();
    }

    @Override
    public String getSigAlgOID() {
        return delegate.getSigAlgOID();
    }

    @Override
    public byte[] getSigAlgParams() {
        return delegate.getSigAlgParams();
    }

    @Override
    public boolean[] getIssuerUniqueID() {
        return delegate.getIssuerUniqueID();
    }

    @Override
    public boolean[] getSubjectUniqueID() {
        return delegate.getSubjectUniqueID();
    }

    @Override
    public boolean[] getKeyUsage() {
        return delegate.getKeyUsage();
    }

    @Override
    public int getBasicConstraints() {
        return delegate.getBasicConstraints();
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        return delegate.getEncoded();
    }

    @Override
    public void verify(PublicKey key)
            throws CertificateException,
                    NoSuchAlgorithmException,
                    InvalidKeyException,
                    NoSuchProviderException,
                    SignatureException {
        delegate.verify(key);
    }

    @Override
    public void verify(PublicKey key, String provider)
            throws CertificateException,
                    NoSuchAlgorithmException,
                    InvalidKeyException,
                    NoSuchProviderException,
                    SignatureException {
        delegate.verify(key, provider);
    }

    @Override
    public String toString() {
        return "X509 certificate (time checks explicitly disabled)";
    }

    @Override
    public PublicKey getPublicKey() {
        return delegate.getPublicKey();
    }

    @Override
    public Set<String> getCriticalExtensionOIDs() {
        return delegate.getCriticalExtensionOIDs();
    }

    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
        return delegate.getNonCriticalExtensionOIDs();
    }

    @Override
    public byte[] getExtensionValue(String oid) {
        return delegate.getExtensionValue(oid);
    }

    @Override
    public boolean hasUnsupportedCriticalExtension() {
        return delegate.hasUnsupportedCriticalExtension();
    }
}
