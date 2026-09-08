package kalkan.worker;

import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.ASN1Object;
import kz.gov.pki.kalkan.asn1.ASN1OctetString;
import kz.gov.pki.kalkan.asn1.DERObject;
import kz.gov.pki.kalkan.asn1.x509.SubjectPublicKeyInfo;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedGenerator;

import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;

/** Shared provider algorithms and strict ASN.1 parsing used by crypto operations. */
final class CryptoSupport {
    static final String PROVIDER = KalkanProvider.PROVIDER_NAME;
    static final byte[] EMPTY = new byte[0];
    static final long CLOCK_SKEW = 5 * 60 * 1000L;

    private CryptoSupport() {}

    static final class Algorithm {
        final String digest;
        final String digestOID;
        final String signature;
        final String signatureOID;
        final int digestSize;

        Algorithm(
                String digest,
                String digestOID,
                String signature,
                String signatureOID,
                int digestSize) {
            this.digest = digest;
            this.digestOID = digestOID;
            this.signature = signature;
            this.signatureOID = signatureOID;
            this.digestSize = digestSize;
        }
    }

    static String hashName(String name) throws Failure {
        return switch (name) {
            case "sha256", "SHA256" -> "SHA-256";
            case "GOST95", "Gost34311_95" -> CMSSignedGenerator.DIGEST_GOST34311_95;
            case "GOST2015_256", "GostR3411_2015_256" -> "GOST3411-2015-256";
            case "GOST2015_512", "GostR3411_2015_512" -> "GOST3411-2015-512";
            default -> throw new Failure(Failure.UNSUPPORTED, "Unsupported hash algorithm");
        };
    }

    static Algorithm algorithm(X509Certificate certificate) throws Exception {
        SubjectPublicKeyInfo publicKey =
                SubjectPublicKeyInfo.getInstance(
                        ASN1Object.fromByteArray(certificate.getPublicKey().getEncoded()));
        String oid = publicKey.getAlgorithmId().getObjectId().getId();

        return switch (oid) {
            case "1.2.840.113549.1.1.1" ->
                    new Algorithm(
                            "SHA-256",
                            CMSSignedGenerator.DIGEST_SHA256,
                            "SHA256withRSA",
                            CMSSignedGenerator.ENCRYPTION_RSA,
                            32);
            case "1.2.398.3.10.1.1.2.1" ->
                    new Algorithm(
                            "GOST3411-2015-256",
                            CMSSignedGenerator.DIGEST_GOST3411_2015_256,
                            "ECGOST3410-2015-256",
                            CMSSignedGenerator.ENCRYPTION_ECGOST3410_2015_256,
                            32);
            case "1.2.398.3.10.1.1.2.2" ->
                    new Algorithm(
                            "GOST3411-2015-512",
                            CMSSignedGenerator.DIGEST_GOST3411_2015_512,
                            "ECGOST3410-2015-512",
                            CMSSignedGenerator.ENCRYPTION_ECGOST3410_2015_512,
                            64);
            case "1.2.398.3.10.1.1.1.1" ->
                    new Algorithm(
                            CMSSignedGenerator.DIGEST_GOST34311_95,
                            CMSSignedGenerator.DIGEST_GOST34311_95,
                            "ECGOST34310",
                            CMSSignedGenerator.ENCRYPTION_ECGOST34310_2004_WITH_GOST34311_95_TEST,
                            32);
            default ->
                    throw new Failure(
                            Failure.UNSUPPORTED, "Unsupported signing public-key algorithm");
        };
    }

    static void checkSigningUsage(X509Certificate certificate) throws Failure {
        boolean[] usage = certificate.getKeyUsage();
        if (usage != null
                && (usage.length == 0 || (!usage[0] && (usage.length < 2 || !usage[1])))) {
            throw new Failure(
                    Failure.CRYPTO_ERROR, "Certificate key usage does not permit document signing");
        }
    }

    static void requireDigitalSignature(X509Certificate certificate, String purpose)
            throws Failure {
        boolean[] usage = certificate.getKeyUsage();
        if (usage != null && (usage.length == 0 || !usage[0])) {
            throw new Failure(
                    Failure.CRYPTO_ERROR,
                    purpose + " certificate does not permit digital signatures");
        }
    }

    static ASN1Object singleASN1(byte[] encoded) throws Exception {
        try (ASN1InputStream input = new ASN1InputStream(encoded)) {
            DERObject object = input.readObject();
            if (!(object instanceof ASN1Object parsed) || input.readObject() != null) {
                throw new Failure(Failure.CRYPTO_ERROR, "Expected exactly one ASN.1 object");
            }
            return parsed;
        }
    }

    static ASN1Object extensionObject(X509Extension value, String oid) throws Exception {
        byte[] encoded = value.getExtensionValue(oid);
        if (encoded == null) {
            return null;
        }
        ASN1OctetString extension = ASN1OctetString.getInstance(singleASN1(encoded));
        return singleASN1(extension.getOctets());
    }
}
