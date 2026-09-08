package kalkan.worker;

import static kalkan.worker.CryptoSupport.PROVIDER;
import static kalkan.worker.XmlDocument.DS;
import static kalkan.worker.XmlDocument.WSSE;
import static kalkan.worker.XmlDocument.children;
import static kalkan.worker.XmlDocument.one;

import kz.gov.pki.kalkan.asn1.knca.KNCAObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;

import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Supported signature profiles, embedded certificates and cryptographic verification. */
final class XmlSignatures {
    static final String ENVELOPED = DS + "enveloped-signature";
    static final String EXCLUSIVE = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private static final String CANONICAL_10 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    private static final String CANONICAL_11 = "http://www.w3.org/2006/12/xml-c14n11";
    private static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private static final String RSA_SHA1 = DS + "rsa-sha1";
    private static final String RSA_SHA1_ALTERNATIVE =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1";
    private static final String GOST_95 =
            "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311";
    private static final String GOST_2015_512 =
            "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512";
    private static final String TOKEN_BASE64 =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
    private static final String TOKEN_X509 =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
    private static final String TOKEN_X509_LEGACY = TOKEN_X509.replace("#X509v3", "#X509");
    private static final Set<String> CANONICAL_ALGORITHMS =
            Set.of(
                    CANONICAL_10, CANONICAL_10 + "#WithComments",
                    CANONICAL_11, CANONICAL_11 + "#WithComments",
                    EXCLUSIVE, EXCLUSIVE + "WithComments");

    record SigningAlgorithms(String signatureURI, String digestURI) {}

    private record AlgorithmMetadata(String name, String oid) {}

    private XmlSignatures() {}

    static String canonicalization(int flags) throws Failure {
        return switch (flags) {
            case 0x01000001 -> CANONICAL_10;
            case 0x01000002 -> CANONICAL_10 + "#WithComments";
            case 0x01000004 -> CANONICAL_11;
            case 0x01000008 -> CANONICAL_11 + "#WithComments";
            case 0x01000010 -> EXCLUSIVE;
            case 0x01000020 -> EXCLUSIVE + "WithComments";
            default ->
                    throw new Failure(
                            Failure.UNSUPPORTED, "Unsupported XML canonicalization flags");
        };
    }

    static SigningAlgorithms signingAlgorithms(X509Certificate certificate) throws Exception {
        CryptoSupport.Algorithm algorithm = CryptoSupport.algorithm(certificate);
        return switch (algorithm.digest) {
            case "SHA-256" ->
                    new SigningAlgorithms(RSA_SHA256, "http://www.w3.org/2001/04/xmlenc#sha256");
            case "GOST3411-2015-512" ->
                    new SigningAlgorithms(
                            GOST_2015_512,
                            "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512");
            default -> {
                if (!algorithm.signature.equals("ECGOST34310")) {
                    throw new Failure(
                            Failure.UNSUPPORTED,
                            "The installed XML adapter does not support this signing key"
                                    + " algorithm");
                }
                yield new SigningAlgorithms(
                        GOST_95, "http://www.w3.org/2001/04/xmldsig-more#gost34311");
            }
        };
    }

    static String describeAlgorithm(byte[] encoded) throws Exception {
        Element signature = XmlDocument.signatures(XmlDocument.parseDOM(encoded)).get(0);
        Element method = one(one(signature, DS, "SignedInfo"), DS, "SignatureMethod");
        AlgorithmMetadata algorithm = algorithmMetadata(method.getAttribute("Algorithm"));
        return "signatureAlgorithm=" + algorithm.name() + "(" + algorithm.oid() + ")";
    }

    private static AlgorithmMetadata algorithmMetadata(String uri) throws Failure {
        return switch (uri) {
            case RSA_SHA256 ->
                    new AlgorithmMetadata(
                            "sha256WithRSAEncryption",
                            PKCSObjectIdentifiers.sha256WithRSAEncryption.getId());
            case RSA_SHA1, RSA_SHA1_ALTERNATIVE ->
                    new AlgorithmMetadata(
                            "sha1WithRSAEncryption",
                            PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            case GOST_95 ->
                    new AlgorithmMetadata(
                            "GOST 34.311-95 with GOST 34.310-2004",
                            KNCAObjectIdentifiers.gost34311_95_with_gost34310_2004.getId());
            case GOST_2015_512 ->
                    new AlgorithmMetadata(
                            "GOST R 34.10-2015 with GOST R 34.11-2015 (512 bit)",
                            KNCAObjectIdentifiers.gost3411_2015_with_gost3410_2015_512.getId());
            default ->
                    throw new Failure(Failure.UNSUPPORTED, "Unsupported XML signature algorithm");
        };
    }

    static void checkStructure(Element signature, XmlDocument document) throws Exception {
        Element signedInfo = one(signature, DS, "SignedInfo");
        one(signature, DS, "SignatureValue");
        if (!children(signature, DS, "Object").isEmpty()) {
            throw new Failure(
                    Failure.UNSUPPORTED,
                    "XML Objects, XAdES and XML timestamp validation are unsupported");
        }
        checkSignedInfoAlgorithms(signedInfo);
        List<Element> references = children(signedInfo, DS, "Reference");
        if (references.isEmpty() || references.size() > 30) {
            throw new Failure(
                    Failure.INVALID_ARGUMENT,
                    "XML must contain between 1 and 30 references per signature");
        }
        for (Element reference : references) {
            checkReference(reference, document);
        }
    }

    private static void checkSignedInfoAlgorithms(Element signedInfo) throws Failure {
        canonicalParameters(one(signedInfo, DS, "CanonicalizationMethod"));
        algorithmMetadata(one(signedInfo, DS, "SignatureMethod").getAttribute("Algorithm"));
    }

    private static void canonicalParameters(Element element) throws Failure {
        String algorithm = element.getAttribute("Algorithm");
        if (!CANONICAL_ALGORITHMS.contains(algorithm)) {
            throw new Failure(Failure.UNSUPPORTED, "Unsupported XML canonicalization algorithm");
        }
        int parameters = 0;
        for (Node node = element.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (!(node instanceof Element parameter)) {
                continue;
            }
            boolean exclusive =
                    algorithm.equals(EXCLUSIVE) || algorithm.equals(EXCLUSIVE + "WithComments");
            if (!exclusive
                    || !EXCLUSIVE.equals(parameter.getNamespaceURI())
                    || !parameter.getLocalName().equals("InclusiveNamespaces")
                    || !parameter.hasAttribute("PrefixList")
                    || ++parameters > 1
                    || parameter.getElementsByTagName("*").getLength() != 0) {
                throw new Failure(
                        Failure.UNSUPPORTED, "Unsupported XML canonicalization parameters");
            }
        }
    }

    private static void checkReference(Element reference, XmlDocument document) throws Failure {
        String uri = reference.getAttribute("URI");
        if (!uri.isEmpty()) {
            Element target = uri.startsWith("#") ? document.elementByID(uri.substring(1)) : null;
            if (target == null) {
                throw new Failure(
                        Failure.INVALID_ARGUMENT,
                        "Only local XML references to unique element IDs are permitted");
            }
            if (DS.equals(target.getNamespaceURI())) {
                throw new Failure(
                        Failure.UNSUPPORTED,
                        "References to XML signature metadata are unsupported");
            }
        }
        List<Element> containers = children(reference, DS, "Transforms");
        if (containers.size() > 1) {
            throw new Failure(
                    Failure.INVALID_ARGUMENT,
                    "XML reference contains multiple Transforms elements");
        }
        if (!containers.isEmpty()) {
            checkTransforms(containers.get(0));
        }
    }

    private static void checkTransforms(Element container) throws Failure {
        List<Element> transforms = children(container, DS, "Transform");
        if (transforms.isEmpty() || transforms.size() > 2) {
            throw new Failure(Failure.UNSUPPORTED, "Unsupported XML transform sequence");
        }
        boolean enveloped = false;
        boolean canonical = false;
        for (Element transform : transforms) {
            String algorithm = transform.getAttribute("Algorithm");
            if (algorithm.equals(ENVELOPED)) {
                if (enveloped
                        || canonical
                        || transform.getElementsByTagName("*").getLength() != 0) {
                    throw new Failure(
                            Failure.UNSUPPORTED,
                            "Unsupported enveloped XML transform parameters or order");
                }
                enveloped = true;
            } else {
                if (canonical) {
                    throw new Failure(
                            Failure.UNSUPPORTED, "Repeated XML canonicalization transform");
                }
                canonicalParameters(transform);
                canonical = true;
            }
        }
    }

    static void addWSSECertificate(XMLSignature signature, X509Certificate certificate)
            throws Exception {
        // Match Linux KalkanCrypt's embedded X509v3 KeyIdentifier form.
        // SDK 2.0.13 does not locate the certificate through a token URI.
        Document document = signature.getElement().getOwnerDocument();
        Element tokenReference = document.createElementNS(WSSE, "wsse:SecurityTokenReference");
        Element identifier = document.createElementNS(WSSE, "wsse:KeyIdentifier");
        identifier.setAttribute("EncodingType", TOKEN_BASE64);
        identifier.setAttribute("ValueType", TOKEN_X509);
        identifier.setTextContent(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        tokenReference.appendChild(identifier);
        signature.getKeyInfo().getElement().appendChild(tokenReference);
    }

    static List<X509Certificate> embeddedCertificates(Element signature, XmlDocument document)
            throws Exception {
        List<X509Certificate> certificates = new ArrayList<>();
        List<Element> infos = children(signature, DS, "KeyInfo");
        if (infos.isEmpty()) {
            return certificates;
        }
        if (infos.size() != 1) {
            throw new Failure(
                    Failure.INVALID_ARGUMENT, "XML signature contains multiple KeyInfo elements");
        }
        for (Node node = infos.get(0).getFirstChild(); node != null; node = node.getNextSibling()) {
            if (!(node instanceof Element element)) {
                continue;
            }
            if (DS.equals(element.getNamespaceURI()) && element.getLocalName().equals("X509Data")) {
                for (Element certificate : children(element, DS, "X509Certificate")) {
                    certificates.add(parseCertificate(certificate.getTextContent()));
                }
            } else if (WSSE.equals(element.getNamespaceURI())
                    && element.getLocalName().equals("SecurityTokenReference")) {
                certificates.add(tokenCertificate(element, document));
            } else {
                throw new Failure(Failure.UNSUPPORTED, "Unsupported XML KeyInfo element");
            }
        }
        return certificates;
    }

    private static X509Certificate tokenCertificate(Element reference, XmlDocument document)
            throws Exception {
        List<Element> identifiers = children(reference, WSSE, "KeyIdentifier");
        if (!identifiers.isEmpty()) {
            if (identifiers.size() != 1 || !children(reference, WSSE, "Reference").isEmpty()) {
                throw new Failure(Failure.INVALID_ARGUMENT, "WSSE token reference is ambiguous");
            }
            Element identifier = identifiers.get(0);
            if (!TOKEN_BASE64.equals(identifier.getAttribute("EncodingType"))
                    || !TOKEN_X509.equals(identifier.getAttribute("ValueType"))) {
                throw new Failure(
                        Failure.UNSUPPORTED,
                        "Only embedded X509v3 KeyIdentifier values are supported");
            }
            return parseCertificate(identifier.getTextContent());
        }
        String uri = one(reference, WSSE, "Reference").getAttribute("URI");
        Element token = uri.startsWith("#") ? document.elementByID(uri.substring(1)) : null;
        if (token == null
                || !WSSE.equals(token.getNamespaceURI())
                || !token.getLocalName().equals("BinarySecurityToken")
                || !TOKEN_BASE64.equals(token.getAttribute("EncodingType"))
                || !(TOKEN_X509.equals(token.getAttribute("ValueType"))
                        || TOKEN_X509_LEGACY.equals(token.getAttribute("ValueType")))) {
            throw new Failure(
                    Failure.UNSUPPORTED,
                    "Only local X509 BinarySecurityToken references are supported");
        }
        return parseCertificate(token.getTextContent());
    }

    private static X509Certificate parseCertificate(String encoded) throws Exception {
        byte[] der;
        try {
            der = Base64.getDecoder().decode(encoded.replaceAll("[\\t\\n\\r ]", ""));
        } catch (IllegalArgumentException error) {
            throw new Failure(Failure.INVALID_ARGUMENT, "XML certificate is not valid base64");
        }
        ByteArrayInputStream input = new ByteArrayInputStream(der);
        X509Certificate certificate =
                (X509Certificate)
                        CertificateFactory.getInstance("X.509", PROVIDER)
                                .generateCertificate(input);
        if (input.available() != 0) {
            throw new Failure(Failure.INVALID_ARGUMENT, "XML certificate has trailing data");
        }
        return certificate;
    }

    static X509Certificate verifyCryptography(Element element, List<X509Certificate> candidates)
            throws Exception {
        XMLSignature signature = new XMLSignature(element, "", true);
        X509Certificate signer = signedInfoSigner(signature, candidates);
        if (!signature.getSignedInfo().verify()) {
            throw new Failure(Failure.CRYPTO_ERROR, "XML referenced content verification failed");
        }
        return signer;
    }

    private static X509Certificate signedInfoSigner(
            XMLSignature signature, List<X509Certificate> candidates) throws Exception {
        SignedInfo signedInfo = signature.getSignedInfo();
        byte[] canonical = signedInfo.getCanonicalizedOctetStream();
        byte[] value = signature.getSignatureValue();
        X509Certificate signer = null;
        for (X509Certificate candidate : new LinkedHashSet<>(candidates)) {
            if (!verifiesSignedInfo(signedInfo, canonical, value, candidate)) {
                continue;
            }
            if (signer != null) {
                throw new Failure(Failure.CRYPTO_ERROR, "XML signer certificate is ambiguous");
            }
            signer = candidate;
        }
        if (signer == null) {
            throw new Failure(Failure.CRYPTO_ERROR, "XML signature verification failed");
        }
        return signer;
    }

    private static boolean verifiesSignedInfo(
            SignedInfo signedInfo, byte[] canonical, byte[] value, X509Certificate certificate)
            throws Exception {
        try {
            SignatureAlgorithm algorithm = signedInfo.getSignatureAlgorithm();
            algorithm.initVerify(certificate.getPublicKey());
            algorithm.update(canonical);
            return algorithm.verify(value);
        } catch (XMLSignatureException error) {
            return false;
        }
    }

    static X509Certificate extractCertificate(Element signature, XmlDocument document)
            throws Exception {
        List<X509Certificate> certificates =
                new ArrayList<>(new LinkedHashSet<>(embeddedCertificates(signature, document)));
        if (certificates.isEmpty()) {
            throw new Failure(Failure.INVALID_ARGUMENT, "XML signer certificate is missing");
        }
        if (certificates.size() == 1) {
            return certificates.get(0);
        }
        // Multiple embedded certificates can be a chain in any order. Select by
        // SignedInfo only: extraction does not verify payload, trust or dates.
        checkSignedInfoAlgorithms(one(signature, DS, "SignedInfo"));
        return signedInfoSigner(new XMLSignature(signature, "", true), certificates);
    }
}
