package kalkan.worker;

import static kalkan.worker.CryptoSupport.PROVIDER;
import static kalkan.worker.Failure.CRYPTO_ERROR;
import static kalkan.worker.Failure.INVALID_ARGUMENT;

import kz.gov.pki.kalkan.asn1.ASN1EncodableVector;
import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.ASN1Object;
import kz.gov.pki.kalkan.asn1.ASN1OctetString;
import kz.gov.pki.kalkan.asn1.ASN1Set;
import kz.gov.pki.kalkan.asn1.DERObject;
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.cms.AttributeTable;
import kz.gov.pki.kalkan.asn1.cms.CMSAttributes;
import kz.gov.pki.kalkan.asn1.cms.CMSObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.cms.ContentInfo;
import kz.gov.pki.kalkan.asn1.cms.SignedData;
import kz.gov.pki.kalkan.asn1.cms.SignerInfo;
import kz.gov.pki.kalkan.asn1.x509.Time;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation;

import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** CMS parsing and signer checks shared by document signatures and timestamp tokens. */
final class CmsSupport {
    private CmsSupport() {}

    static CMSSignedData parseSignedData(byte[] encoded) throws Exception {
        try (ASN1InputStream input = new ASN1InputStream(encoded)) {
            ContentInfo content = ContentInfo.getInstance(input.readObject());
            if (input.readObject() != null
                    || !CMSObjectIdentifiers.signedData.equals(content.getContentType())) {
                throw new Failure(
                        INVALID_ARGUMENT,
                        "Input must contain exactly one CMS SignedData container");
            }
            return new CMSSignedData(content);
        }
    }

    static byte[] attachedContent(CMSSignedData cms) throws Exception {
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        cms.getSignedContent().write(content);
        return content.toByteArray();
    }

    static List<X509Certificate> embeddedCertificates(CMSSignedData cms) throws Exception {
        List<X509Certificate> certificates = new ArrayList<>();
        for (Object entry :
                cms.getCertificatesAndCRLs("Collection", PROVIDER).getCertificates(null)) {
            certificates.add((X509Certificate) entry);
        }
        return certificates;
    }

    static List<X509Certificate> availableCertificates(
            CertificateValidation validation, CMSSignedData cms) throws Exception {
        Set<X509Certificate> certificates = new LinkedHashSet<>(validation.availableCertificates());
        if (cms != null) {
            certificates.addAll(embeddedCertificates(cms));
        }
        return new ArrayList<>(certificates);
    }

    static X509Certificate signerCertificate(
            SignerInformation signer, List<X509Certificate> available) throws Failure {
        X509Certificate match = null;
        for (X509Certificate candidate : available) {
            if (!signer.getSID().match(candidate)) {
                continue;
            }
            if (match != null && !match.equals(candidate)) {
                throw new Failure(
                        CRYPTO_ERROR, "CMS signer identifier matches multiple certificates");
            }
            match = candidate;
        }
        if (match == null) {
            throw new Failure(CRYPTO_ERROR, "CMS signer certificate is unavailable");
        }
        return match;
    }

    static List<SignerInformation> orderedSigners(CMSSignedData cms, byte[] encoded)
            throws Exception {
        // The SDK returns signers through a HashMap; certificate IDs follow wire order.
        Map<SignerInfo, ArrayDeque<SignerInformation>> indexed = new HashMap<>();
        for (Object entry : cms.getSignerInfos().getSigners()) {
            SignerInformation signer = (SignerInformation) entry;
            indexed.computeIfAbsent(signer.toSignerInfo(), ignored -> new ArrayDeque<>())
                    .add(signer);
        }

        ContentInfo content = ContentInfo.getInstance(ASN1Object.fromByteArray(encoded));
        ASN1Set encodedSigners = SignedData.getInstance(content.getContent()).getSignerInfos();
        List<SignerInformation> ordered = new ArrayList<>();
        for (int index = 0; index < encodedSigners.size(); index++) {
            SignerInfo signer = SignerInfo.getInstance(encodedSigners.getObjectAt(index));
            ArrayDeque<SignerInformation> matches = indexed.get(signer);
            if (matches == null || matches.isEmpty()) {
                throw new Failure(CRYPTO_ERROR, "CMS signer list is inconsistent");
            }
            ordered.add(matches.removeFirst());
        }
        return ordered;
    }

    static void validateSignedAttributes(SignerInformation signer, String contentType)
            throws Exception {
        rejectUnsignedContentAttributes(signer.getUnsignedAttributes());

        AttributeTable attributes = signer.getSignedAttributes();
        if (attributes == null) {
            if (!CMSObjectIdentifiers.data.getId().equals(contentType)) {
                throw new Failure(
                        CRYPTO_ERROR, "CMS content other than id-data requires signed attributes");
            }
            return;
        }

        Attribute digest = singleAttribute(attributes, CMSAttributes.messageDigest, true);
        // Require the RFC 5652 OCTET STRING type: the provider skips the content
        // hash comparison for other ASN.1 value types.
        if (!(digest.getAttrValues().getObjectAt(0).getDERObject() instanceof ASN1OctetString)) {
            throw new Failure(CRYPTO_ERROR, "CMS messageDigest must be an OCTET STRING");
        }

        Attribute type = singleAttribute(attributes, CMSAttributes.contentType, true);
        DERObject value = type.getAttrValues().getObjectAt(0).getDERObject();
        if (!(value instanceof DERObjectIdentifier identifier)
                || !identifier.getId().equals(contentType)) {
            throw new Failure(
                    CRYPTO_ERROR, "CMS contentType must match the encapsulated content type");
        }

        Attribute signingTime = singleAttribute(attributes, CMSAttributes.signingTime, false);
        if (signingTime != null) {
            Time.getInstance(signingTime.getAttrValues().getObjectAt(0)).getDate();
        }
        if (attributes.getAll(CMSAttributes.counterSignature).size() != 0) {
            throw new Failure(CRYPTO_ERROR, "CMS countersignatures must be unsigned attributes");
        }
    }

    private static void rejectUnsignedContentAttributes(AttributeTable attributes) throws Failure {
        if (attributes == null) {
            return;
        }
        if (attributes.getAll(CMSAttributes.contentType).size() != 0
                || attributes.getAll(CMSAttributes.messageDigest).size() != 0
                || attributes.getAll(CMSAttributes.signingTime).size() != 0) {
            throw new Failure(
                    CRYPTO_ERROR,
                    "CMS content type, message digest and signing time must be signed attributes");
        }
    }

    private static Attribute singleAttribute(
            AttributeTable attributes, DERObjectIdentifier oid, boolean required) throws Failure {
        ASN1EncodableVector matches = attributes.getAll(oid);
        if (matches.size() == 0 && !required) {
            return null;
        }
        if (matches.size() != 1) {
            throw new Failure(
                    CRYPTO_ERROR, "CMS signed attribute is missing or duplicated: " + oid.getId());
        }

        Attribute attribute = Attribute.getInstance(matches.get(0));
        if (attribute.getAttrValues().size() != 1) {
            throw new Failure(
                    CRYPTO_ERROR,
                    "CMS signed attribute must have exactly one value: " + oid.getId());
        }
        return attribute;
    }
}
