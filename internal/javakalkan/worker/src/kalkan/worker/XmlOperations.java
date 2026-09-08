package kalkan.worker;

import static kalkan.worker.Arguments.string;
import static kalkan.worker.Arguments.utf8;
import static kalkan.worker.CryptoSupport.checkSigningUsage;
import static kalkan.worker.XmlSignatures.ENVELOPED;
import static kalkan.worker.XmlSignatures.EXCLUSIVE;

import kz.gov.pki.kalkan.xmldsig.KncaXS;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Element;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/** Optional Santuario XML/WSSE operations, compiled only with explicit XML dependencies. */
final class XmlOperations implements XmlSupport {
    private static boolean initialized;

    private final KeyStoreState keys;
    private final CertificateValidation validation;

    private enum Profile {
        XML,
        WSSE
    }

    private record SignRequest(
            String alias,
            byte[] xml,
            String nodeID,
            String parentName,
            String parentNamespace,
            String canonicalization,
            boolean skipCertificateTime,
            Profile profile) {}

    XmlOperations(KeyStoreState keys, CertificateValidation validation) {
        this.keys = keys;
        this.validation = validation;
    }

    @Override
    public byte[][] dispatch(int opcode, byte[][] args) throws Exception {
        if (!initialized) {
            KncaXS.loadXMLSecurity();
            initialized = true;
        }
        return new byte[][] {
            switch (opcode) {
                case 30 -> signXML(args);
                case 31 -> verifyXML(args);
                case 32 -> signWSSE(args);
                case 33 -> exportCertificate(args);
                case 34 -> signatureAlgorithm(args);
                default -> throw new Failure(Failure.UNSUPPORTED, "Unsupported XML operation");
            }
        };
    }

    private byte[] signXML(byte[][] args) throws Exception {
        count(args, 7);
        return sign(
                new SignRequest(
                        string(args[0]),
                        args[1],
                        string(args[2]),
                        string(args[3]),
                        string(args[4]),
                        canonical(args[5]),
                        bool(args[6]),
                        Profile.XML));
    }

    private byte[] verifyXML(byte[][] args) throws Exception {
        count(args, 4);
        canonical(args[2]);
        return verify(string(args[0]), args[1], bool(args[3]));
    }

    private byte[] signWSSE(byte[][] args) throws Exception {
        count(args, 5);
        return sign(
                new SignRequest(
                        string(args[0]),
                        args[1],
                        string(args[2]),
                        "",
                        "",
                        canonical(args[3]),
                        bool(args[4]),
                        Profile.WSSE));
    }

    private static byte[] exportCertificate(byte[][] args) throws Exception {
        count(args, 2);
        int index = integer(args[1]);
        XmlDocument document = XmlDocument.parse(args[0]);
        List<Element> signatures = document.signatures();
        int position = index == 0 ? 0 : index - 1;
        if (position >= signatures.size()) {
            return new byte[0];
        }
        return XmlSignatures.extractCertificate(signatures.get(position), document).getEncoded();
    }

    private static byte[] signatureAlgorithm(byte[][] args) throws Exception {
        count(args, 1);
        return utf8(XmlSignatures.describeAlgorithm(args[0]));
    }

    private byte[] sign(SignRequest request) throws Exception {
        XmlDocument document = XmlDocument.parse(request.xml());
        int existingCount = document.signatureCount();
        if (existingCount >= 64 || request.profile() == Profile.WSSE && existingCount != 0) {
            throw new Failure(
                    Failure.UNSUPPORTED,
                    "Cannot append another signature to this XML signature profile");
        }
        Element target = document.signingTarget(request.nodeID());
        Element parent =
                request.profile() == Profile.WSSE
                        ? document.securityHeader(target, request.nodeID())
                        : document.signatureParent(request.parentName(), request.parentNamespace());
        KeyStoreState.KeyEntry key = keys.key(request.alias());
        if (!request.skipCertificateTime()) {
            key.certificate.checkValidity();
        }
        checkSigningUsage(key.certificate);
        XMLSignature signature = createSignature(document, parent, key.certificate, request);
        signature.sign(key.key);
        byte[] result = document.serialize();
        verifyPreservedSignatures(result, key.certificate, existingCount);
        return result;
    }

    private static XMLSignature createSignature(
            XmlDocument document, Element parent, X509Certificate certificate, SignRequest request)
            throws Exception {
        XmlSignatures.SigningAlgorithms algorithms = XmlSignatures.signingAlgorithms(certificate);
        XMLSignature signature =
                new XMLSignature(
                        document.dom(), "", algorithms.signatureURI(), request.canonicalization());
        parent.appendChild(signature.getElement());
        Transforms transforms = new Transforms(document.dom());
        if (request.profile() == Profile.XML) {
            transforms.addTransform(ENVELOPED);
        }
        // The SOAP verifier permits only exclusive canonicalization on the Body
        // reference. The request controls SignedInfo canonicalization.
        transforms.addTransform(
                request.profile() == Profile.WSSE ? EXCLUSIVE : request.canonicalization());
        String reference = request.nodeID().isEmpty() ? "" : "#" + request.nodeID();
        signature.addDocument(reference, transforms, algorithms.digestURI());
        if (request.profile() == Profile.WSSE) {
            XmlSignatures.addWSSECertificate(signature, certificate);
        } else {
            signature.addKeyInfo(certificate);
        }
        return signature;
    }

    private static void verifyPreservedSignatures(
            byte[] encoded, X509Certificate certificate, int existingCount) throws Exception {
        // Serialization and appended signatures can change signed bytes. Verify
        // every signature without applying trust or time policy to existing signers.
        XmlDocument serialized = XmlDocument.parse(encoded);
        for (Element element : serialized.signatures()) {
            XmlSignatures.checkStructure(element, serialized);
            List<X509Certificate> candidates =
                    XmlSignatures.embeddedCertificates(element, serialized);
            candidates.add(certificate);
            try {
                XmlSignatures.verifyCryptography(element, candidates);
            } catch (Exception error) {
                int status = existingCount == 0 ? Failure.CRYPTO_ERROR : Failure.UNSUPPORTED;
                throw new Failure(
                        status,
                        "Signing would return an invalid XML signature or invalidate an existing"
                                + " signature");
            }
        }
    }

    private byte[] verify(String alias, byte[] encoded, boolean skipTime) throws Exception {
        XmlDocument document = XmlDocument.parse(encoded);
        List<Element> signatures = document.signatures();
        List<X509Certificate> available = validation.availableCertificates();
        for (Element element : signatures) {
            available.addAll(XmlSignatures.embeddedCertificates(element, document));
        }
        for (Element element : signatures) {
            XmlSignatures.checkStructure(element, document);
            List<X509Certificate> candidates =
                    XmlSignatures.embeddedCertificates(element, document);
            if (!alias.isEmpty()) {
                candidates.add(keys.key(alias).certificate);
            }
            X509Certificate signer = XmlSignatures.verifyCryptography(element, candidates);
            if (!skipTime) {
                signer.checkValidity();
            }
            checkSigningUsage(signer);
            validation.checkRevocation(
                    validation.validateChain(
                            signer,
                            available,
                            skipTime,
                            new Date(),
                            "XML/WS-Security signer certificate"));
        }
        return utf8(
                "Verify XML - OK; signatures="
                        + signatures.size()
                        + "; trust chain=OK; certificate time="
                        + (skipTime ? "skipped" : "checked")
                        + "; revocation="
                        + validation.revocationDiagnostic());
    }

    private static void count(byte[][] args, int expected) throws Failure {
        if (args.length != expected) {
            throw new Failure(Failure.INVALID_ARGUMENT, "Incorrect XML argument count");
        }
    }

    private static int integer(byte[] value) throws Failure {
        try {
            int result = Integer.parseInt(string(value));
            if (result >= 0) {
                return result;
            }
        } catch (NumberFormatException ignored) {
            // Malformed and negative values share the same protocol error.
        }
        throw new Failure(Failure.INVALID_ARGUMENT, "Invalid XML integer argument");
    }

    private static boolean bool(byte[] value) throws Failure {
        return switch (string(value)) {
            case "1" -> true;
            case "0" -> false;
            default -> throw new Failure(Failure.INVALID_ARGUMENT, "Invalid XML boolean argument");
        };
    }

    private static String canonical(byte[] flags) throws Failure {
        return XmlSignatures.canonicalization(integer(flags));
    }
}
