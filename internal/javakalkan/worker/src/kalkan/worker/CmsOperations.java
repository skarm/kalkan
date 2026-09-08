package kalkan.worker;

import static kalkan.worker.Arguments.utf8;
import static kalkan.worker.CryptoSupport.EMPTY;
import static kalkan.worker.CryptoSupport.PROVIDER;
import static kalkan.worker.CryptoSupport.algorithm;
import static kalkan.worker.CryptoSupport.checkSigningUsage;
import static kalkan.worker.CryptoSupport.singleASN1;
import static kalkan.worker.Failure.CRYPTO_ERROR;
import static kalkan.worker.Failure.INVALID_ARGUMENT;
import static kalkan.worker.Failure.UNSUPPORTED;

import kalkan.worker.CryptoSupport.Algorithm;

import kz.gov.pki.kalkan.asn1.ASN1Encodable;
import kz.gov.pki.kalkan.asn1.ASN1EncodableVector;
import kz.gov.pki.kalkan.asn1.ASN1Object;
import kz.gov.pki.kalkan.asn1.ASN1Set;
import kz.gov.pki.kalkan.asn1.DEREncodable;
import kz.gov.pki.kalkan.asn1.DERNull;
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.asn1.DEROctetString;
import kz.gov.pki.kalkan.asn1.DERSet;
import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.cms.CMSAttributes;
import kz.gov.pki.kalkan.asn1.cms.CMSObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.cms.ContentInfo;
import kz.gov.pki.kalkan.asn1.cms.IssuerAndSerialNumber;
import kz.gov.pki.kalkan.asn1.cms.SignedData;
import kz.gov.pki.kalkan.asn1.cms.SignerIdentifier;
import kz.gov.pki.kalkan.asn1.cms.SignerInfo;
import kz.gov.pki.kalkan.asn1.x509.AlgorithmIdentifier;
import kz.gov.pki.kalkan.asn1.x509.TBSCertificateStructure;
import kz.gov.pki.kalkan.asn1.x509.Time;
import kz.gov.pki.kalkan.jce.provider.cms.CMSProcessableByteArray;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation;

import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Document CMS signing, verification and signer extraction. */
final class CmsOperations {
    record SignOptions(
            boolean detached,
            boolean includeCertificate,
            boolean skipCertificateTime,
            boolean timestamp) {}

    private final KeyStoreState keys;
    private final CertificateValidation validation;
    private final TimestampOperations timestamps;

    CmsOperations(KeyStoreState keys, CertificateValidation validation, EvidenceFetcher transport) {
        this.keys = keys;
        this.validation = validation;
        timestamps = new TimestampOperations(validation, transport);
    }

    void setTimestampURL(String url) {
        timestamps.setAuthorityURL(url);
    }

    byte[] sign(String alias, byte[] data, SignOptions options, byte[] existingCMS)
            throws Exception {
        SignedData previous = validatePreviousCMS(existingCMS, data, options);
        KeyStoreState.KeyEntry entry = signingKey(alias, options.skipCertificateTime());
        Algorithm algorithm = algorithm(entry.certificate);
        byte[] digest = MessageDigest.getInstance(algorithm.digest, PROVIDER).digest(data);
        return createSignedData(entry, algorithm, digest, data, options, previous);
    }

    byte[] signHash(String alias, byte[] digest, SignOptions options) throws Exception {
        KeyStoreState.KeyEntry entry = signingKey(alias, options.skipCertificateTime());
        Algorithm algorithm = algorithm(entry.certificate);
        if (digest.length != algorithm.digestSize) {
            throw new Failure(
                    INVALID_ARGUMENT, "Digest length does not match the signing key algorithm");
        }
        return createSignedData(entry, algorithm, digest, digest, options, null);
    }

    byte[][] verify(
            byte[] encoded,
            byte[] data,
            boolean detached,
            int signerID,
            boolean skipTime,
            String alias)
            throws Exception {
        CMSSignedData parsed = CmsSupport.parseSignedData(encoded);
        boolean hasContent = parsed.getSignedContent() != null;
        if (detached == hasContent) {
            throw new Failure(INVALID_ARGUMENT, "Detached flag does not match the CMS container");
        }
        CMSSignedData cms =
                detached ? new CMSSignedData(new CMSProcessableByteArray(data), encoded) : parsed;
        List<X509Certificate> available = CmsSupport.availableCertificates(validation, cms);
        List<SignerInformation> signers = CmsSupport.orderedSigners(cms, encoded);
        if (signers.isEmpty()) {
            throw new Failure(CRYPTO_ERROR, "CMS contains no signers");
        }
        if (signerID > signers.size()) {
            throw new Failure(INVALID_ARGUMENT, "Signer index is outside the CMS signer list");
        }

        // An alias supplies an external certificate for certificate-free CMS.
        if (!alias.isEmpty()) {
            available.add(keys.key(alias).certificate);
        }
        byte[] selected = EMPTY;
        int verifiedTimestamps = 0;
        for (int index = 0; index < signers.size(); index++) {
            SignerInformation signer = signers.get(index);
            X509Certificate certificate =
                    verifySigner(signer, cms.getSignedContentTypeOID(), available, skipTime);
            verifiedTimestamps += timestamps.validateTimestamps(signer, available);
            if (index + 1 == signerID) {
                selected = certificate.getEncoded();
            }
        }

        byte[] content = detached ? EMPTY : CmsSupport.attachedContent(cms);
        String report = verificationReport(signers.size(), skipTime, verifiedTimestamps);
        return new byte[][] {content, selected, utf8(report)};
    }

    byte[] getCertificate(byte[] encoded, int oneBasedID) throws Exception {
        if (oneBasedID == 0) {
            return EMPTY;
        }
        CMSSignedData cms = CmsSupport.parseSignedData(encoded);
        List<SignerInformation> signers = CmsSupport.orderedSigners(cms, encoded);
        if (signers.isEmpty()) {
            throw new Failure(CRYPTO_ERROR, "CMS contains no signers");
        }
        if (oneBasedID > signers.size()) {
            return EMPTY;
        }

        SignerInformation signer = signers.get(oneBasedID - 1);
        List<X509Certificate> embedded = CmsSupport.embeddedCertificates(cms);
        return CmsSupport.signerCertificate(signer, embedded).getEncoded();
    }

    Date getTimestamp(byte[] encoded, int zeroBasedID) throws Exception {
        CMSSignedData cms = CmsSupport.parseSignedData(encoded);
        List<SignerInformation> signers = CmsSupport.orderedSigners(cms, encoded);
        if (zeroBasedID >= signers.size()) {
            throw new Failure(INVALID_ARGUMENT, "Signer index is outside the CMS signer list");
        }
        SignerInformation signer = signers.get(zeroBasedID);
        List<X509Certificate> available = CmsSupport.availableCertificates(validation, cms);
        return timestamps.earliestVerifiedTimestamp(signer, available);
    }

    private SignedData validatePreviousCMS(byte[] encoded, byte[] data, SignOptions options)
            throws Exception {
        if (encoded.length == 0) {
            return null;
        }
        CMSSignedData existing = CmsSupport.parseSignedData(encoded);
        if (!options.detached()
                && existing.getSignedContent() != null
                && !Arrays.equals(data, CmsSupport.attachedContent(existing))) {
            throw new Failure(
                    INVALID_ARGUMENT, "Data does not match the existing attached CMS content");
        }

        verify(encoded, data, options.detached(), 0, options.skipCertificateTime(), "");
        ContentInfo content = ContentInfo.getInstance(singleASN1(encoded));
        SignedData previous = SignedData.getInstance(content.getContent());
        if (!CMSObjectIdentifiers.data.equals(previous.getEncapContentInfo().getContentType())) {
            throw new Failure(UNSUPPORTED, "Appending a signer requires CMS id-data content");
        }
        return previous;
    }

    private KeyStoreState.KeyEntry signingKey(String alias, boolean skipTime) throws Exception {
        KeyStoreState.KeyEntry entry = keys.key(alias);
        if (!skipTime) {
            entry.certificate.checkValidity();
        }
        checkSigningUsage(entry.certificate);
        return entry;
    }

    private byte[] createSignedData(
            KeyStoreState.KeyEntry entry,
            Algorithm algorithm,
            byte[] digest,
            byte[] data,
            SignOptions options,
            SignedData previous)
            throws Exception {
        AlgorithmIdentifier digestAlgorithm =
                new AlgorithmIdentifier(
                        new DERObjectIdentifier(algorithm.digestOID), new DERNull());
        SignerInfo signer =
                createSigner(entry, algorithm, digestAlgorithm, digest, options.timestamp());
        ASN1Set certificates =
                options.includeCertificate()
                        ? new DERSet(ASN1Object.fromByteArray(entry.certificate.getEncoded()))
                        : null;
        ContentInfo content =
                new ContentInfo(
                        CMSObjectIdentifiers.data,
                        options.detached() ? null : new DEROctetString(data));
        ASN1Set algorithms = new DERSet(digestAlgorithm);
        ASN1Set signers = new DERSet(signer);
        ASN1Set crls = null;
        if (previous != null) {
            content = previous.getEncapContentInfo();
            crls = previous.getCRLs();
            algorithms = mergeSet(previous.getDigestAlgorithms(), algorithms);
            certificates = mergeSet(previous.getCertificates(), certificates);
            signers = appendSigner(previous.getSignerInfos(), signer);
        }

        SignedData signed = new SignedData(algorithms, content, certificates, crls, signers);
        return new ContentInfo(CMSObjectIdentifiers.signedData, signed)
                .getEncoded(ASN1Encodable.DER);
    }

    private SignerInfo createSigner(
            KeyStoreState.KeyEntry entry,
            Algorithm algorithm,
            AlgorithmIdentifier digestAlgorithm,
            byte[] digest,
            boolean timestamp)
            throws Exception {
        DERSet signedAttributes = signedAttributes(digest);
        Signature signer = Signature.getInstance(algorithm.signature, PROVIDER);
        signer.initSign(entry.key);
        signer.update(signedAttributes.getEncoded(ASN1Encodable.DER));

        AlgorithmIdentifier signatureAlgorithm =
                new AlgorithmIdentifier(
                        new DERObjectIdentifier(algorithm.signatureOID), new DERNull());
        TBSCertificateStructure certificate =
                TBSCertificateStructure.getInstance(
                        ASN1Object.fromByteArray(entry.certificate.getTBSCertificate()));
        SignerIdentifier identifier =
                new SignerIdentifier(
                        new IssuerAndSerialNumber(
                                certificate.getIssuer(), entry.certificate.getSerialNumber()));
        byte[] signature = signer.sign();
        DERSet unsignedAttributes =
                timestamp ? new DERSet(timestamps.createTimestampAttribute(signature)) : null;
        return new SignerInfo(
                identifier,
                digestAlgorithm,
                signedAttributes,
                signatureAlgorithm,
                new DEROctetString(signature),
                unsignedAttributes);
    }

    private static DERSet signedAttributes(byte[] digest) {
        ASN1EncodableVector attributes = new ASN1EncodableVector();
        attributes.add(
                new Attribute(CMSAttributes.contentType, new DERSet(CMSObjectIdentifiers.data)));
        attributes.add(
                new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(digest))));
        attributes.add(new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date()))));
        return new DERSet(attributes);
    }

    private static ASN1Set appendSigner(ASN1Set previous, SignerInfo signer) {
        ASN1EncodableVector signers = new ASN1EncodableVector();
        for (int index = 0; index < previous.size(); index++) {
            signers.add(previous.getObjectAt(index));
        }
        signers.add(signer);
        return new DERSet(signers);
    }

    private static ASN1Set mergeSet(ASN1Set first, ASN1Set second) {
        if (first == null) {
            return second;
        }
        if (second == null) {
            return first;
        }

        ASN1EncodableVector merged = new ASN1EncodableVector();
        Set<DEREncodable> seen = new LinkedHashSet<>();
        for (ASN1Set source : new ASN1Set[] {first, second}) {
            for (int index = 0; index < source.size(); index++) {
                DEREncodable value = source.getObjectAt(index);
                if (seen.add(value)) {
                    merged.add(value);
                }
            }
        }
        return new DERSet(merged);
    }

    private X509Certificate verifySigner(
            SignerInformation signer,
            String contentType,
            List<X509Certificate> available,
            boolean skipTime)
            throws Exception {
        CmsSupport.validateSignedAttributes(signer, contentType);
        X509Certificate certificate = CmsSupport.signerCertificate(signer, available);
        if (!skipTime) {
            certificate.checkValidity();
        }
        checkSigningUsage(certificate);
        // The PublicKey overload avoids the provider's implicit signing-time validity check.
        if (!signer.verify(certificate.getPublicKey(), PROVIDER)) {
            throw new Failure(CRYPTO_ERROR, "CMS signature verification failed");
        }

        List<X509Certificate> chain =
                validation.validateChain(
                        certificate, available, skipTime, new Date(), "CMS signer certificate");
        validation.checkRevocation(chain);
        return certificate;
    }

    private String verificationReport(int signers, boolean skipTime, int verifiedTimestamps) {
        return "Verify - OK; signers="
                + signers
                + "; trust chain=OK; certificate time="
                + (skipTime ? "skipped" : "checked")
                + "; revocation="
                + validation.revocationDiagnostic()
                + "; timestamps="
                + verifiedTimestamps
                + " verified; countersignatures=none";
    }
}
