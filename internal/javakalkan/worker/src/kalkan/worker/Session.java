package kalkan.worker;

import static kalkan.worker.Arguments.bool;
import static kalkan.worker.Arguments.count;
import static kalkan.worker.Arguments.number;
import static kalkan.worker.Arguments.string;
import static kalkan.worker.Arguments.utf8;
import static kalkan.worker.Arguments.validationTime;
import static kalkan.worker.CryptoSupport.PROVIDER;
import static kalkan.worker.CryptoSupport.hashName;

import java.security.MessageDigest;
import java.util.Date;

/** Routes protocol operations to session-owned keys, trust policy, CMS and optional XML. */
final class Session {
    static final int INITIALIZE = 0;
    static final int CLOSE = 9;
    private static final byte[][] NO_FIELDS = new byte[0][];

    private final Protocol transport;
    private final KeyStoreState keys = new KeyStoreState();
    private final CertificateValidation validation;
    private final CmsOperations cms;
    private final XmlSupport xml;

    Session(Protocol transport, boolean xmlEnabled) throws ReflectiveOperationException {
        this.transport = transport;
        validation = new CertificateValidation(keys, transport);
        cms = new CmsOperations(keys, validation, transport);
        xml = xmlEnabled ? loadXML() : null;
    }

    private XmlSupport loadXML() throws ReflectiveOperationException {
        return (XmlSupport)
                Class.forName("kalkan.worker.XmlOperations")
                        .getDeclaredConstructor(KeyStoreState.class, CertificateValidation.class)
                        .newInstance(keys, validation);
    }

    void beginOperation() {
        validation.beginOperation();
    }

    byte[][] dispatch(int opcode, byte[][] args) throws Exception {
        return switch (opcode) {
            case INITIALIZE -> initialize(args);
            case 1 -> hash(args);
            case 2 -> loadKeyStore(args);
            case 3 -> sign(args);
            case 4 -> verify(args);
            case 5 -> signHash(args);
            case 6 -> cmsCertificate(args);
            case 7 -> loadTrust(args);
            case 8 -> exportCertificate(args);
            case CLOSE -> close(args);
            case 10 -> configureRevocation(args);
            case 11 -> validateCertificate(args);
            case 12 -> configureTimestamp(args);
            case 13 -> signatureTimestamp(args);
            case 30, 31, 32, 33, 34 -> dispatchXML(opcode, args);
            default -> throw new Failure(Failure.UNSUPPORTED, "Unsupported Java worker operation");
        };
    }

    private byte[][] initialize(byte[][] args) throws Failure {
        if (args.length == 1) {
            transport.setOutputLimit(number(args[0]));
        } else {
            count(args, 0);
        }
        return new byte[][] {utf8("kalkan-java/1")};
    }

    private byte[][] hash(byte[][] args) throws Exception {
        count(args, 2);
        String algorithm = hashName(string(args[0]));
        MessageDigest digest = MessageDigest.getInstance(algorithm, PROVIDER);
        return new byte[][] {digest.digest(args[1])};
    }

    private byte[][] loadKeyStore(byte[][] args) throws Exception {
        count(args, 3);
        String path = string(args[0]);
        byte[] password = args[1];
        String alias = string(args[2]);
        keys.loadKeyStore(path, password, alias);
        return NO_FIELDS;
    }

    private byte[][] sign(byte[][] args) throws Exception {
        count(args, 7);
        String alias = string(args[0]);
        byte[] data = args[1];
        boolean detached = bool(args[2]);
        boolean includeCertificate = bool(args[3]);
        boolean skipCertificateTime = bool(args[4]);
        boolean timestamp = bool(args[5]);
        byte[] existingCMS = args[6];
        var options =
                new CmsOperations.SignOptions(
                        detached, includeCertificate, skipCertificateTime, timestamp);
        return new byte[][] {cms.sign(alias, data, options, existingCMS)};
    }

    private byte[][] signHash(byte[][] args) throws Exception {
        count(args, 5);
        String alias = string(args[0]);
        byte[] digest = args[1];
        boolean includeCertificate = bool(args[2]);
        boolean skipCertificateTime = bool(args[3]);
        boolean timestamp = bool(args[4]);
        var options =
                new CmsOperations.SignOptions(
                        true, includeCertificate, skipCertificateTime, timestamp);
        return new byte[][] {cms.signHash(alias, digest, options)};
    }

    private byte[][] verify(byte[][] args) throws Exception {
        count(args, 6);
        byte[] cmsData = args[0];
        byte[] content = args[1];
        boolean detached = bool(args[2]);
        int signerID = number(args[3]);
        boolean skipCertificateTime = bool(args[4]);
        String alias = string(args[5]);
        return cms.verify(cmsData, content, detached, signerID, skipCertificateTime, alias);
    }

    private byte[][] cmsCertificate(byte[][] args) throws Exception {
        count(args, 2);
        return new byte[][] {cms.getCertificate(args[0], number(args[1]))};
    }

    private byte[][] loadTrust(byte[][] args) throws Exception {
        count(args, 2);
        validation.loadTrust(args[0], number(args[1]));
        return NO_FIELDS;
    }

    private byte[][] exportCertificate(byte[][] args) throws Exception {
        count(args, 1);
        return new byte[][] {keys.key(string(args[0])).certificate.getEncoded()};
    }

    private byte[][] close(byte[][] args) throws Failure {
        count(args, 0);
        keys.clear();
        validation.clear();
        return NO_FIELDS;
    }

    private byte[][] configureRevocation(byte[][] args) throws Exception {
        count(args, 3);
        String mode = string(args[0]);
        String source = string(args[1]);
        byte[] localCRLs = args[2];
        validation.configureRevocation(mode, source, localCRLs);
        return NO_FIELDS;
    }

    private byte[][] validateCertificate(byte[][] args) throws Exception {
        count(args, 7);
        byte[] certificate = args[0];
        String revocationMode = string(args[1]);
        String revocationSource = string(args[2]);
        byte[] localCRLs = args[3];
        Date checkTime = validationTime(args[5]);
        boolean returnOCSP = bool(args[6]);
        boolean skipTime = bool(args[4]);
        var request =
                new CertificateValidation.Request(
                        certificate,
                        revocationMode,
                        revocationSource,
                        localCRLs,
                        skipTime,
                        checkTime,
                        returnOCSP);
        return validation.validateCertificate(request);
    }

    private byte[][] configureTimestamp(byte[][] args) throws Failure {
        count(args, 1);
        cms.setTimestampURL(string(args[0]));
        return NO_FIELDS;
    }

    private byte[][] signatureTimestamp(byte[][] args) throws Exception {
        count(args, 2);
        Date timestamp = cms.getTimestamp(args[0], number(args[1]));
        return new byte[][] {utf8(Long.toString(timestamp.getTime()))};
    }

    private byte[][] dispatchXML(int opcode, byte[][] args) throws Exception {
        if (xml == null) {
            throw new Failure(Failure.UNSUPPORTED, "XML operations require WithJavaXMLLibraries");
        }
        return xml.dispatch(opcode, args);
    }
}
