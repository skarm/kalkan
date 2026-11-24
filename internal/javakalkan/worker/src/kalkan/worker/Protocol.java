package kalkan.worker;

import static kalkan.worker.Arguments.string;
import static kalkan.worker.Arguments.utf8;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Arrays;

/** Binary request framing, response limits and host callbacks; owns no cryptographic state. */
final class Protocol implements EvidenceFetcher {
    private static final int SUCCESS = 0;
    private static final int FETCH_REQUEST = 5;
    private static final int FETCH_RESPONSE = 100;
    private static final int MAX_REQUEST_FIELDS = 16;

    private final DataInputStream input;
    private final DataOutputStream output;
    private int maxOutput = 64 * 1024 * 1024;

    Protocol(InputStream input, OutputStream output) {
        this.input = new DataInputStream(new BufferedInputStream(input));
        this.output = new DataOutputStream(new BufferedOutputStream(output));
    }

    void setOutputLimit(int limit) throws Failure {
        if (limit <= 0) {
            throw new Failure(Failure.INVALID_ARGUMENT, "Output limit must be positive");
        }
        maxOutput = limit;
    }

    void serve(Session session) throws IOException {
        while (true) {
            int opcode;
            try {
                opcode = input.readInt();
            } catch (EOFException eof) {
                return;
            }

            byte[][] request;
            try {
                request = readRequest(input);
            } catch (EOFException eof) {
                return;
            } catch (Failure e) {
                writeFailure(e.status, e.getMessage());
                return; // Invalid framing cannot be safely resynchronized.
            }

            if (executeRequest(session, opcode, request)) {
                return;
            }
        }
    }

    private boolean executeRequest(Session session, int opcode, byte[][] request)
            throws IOException {
        try {
            session.beginOperation();
            byte[][] response = session.dispatch(opcode, request);
            if (opcode != Session.INITIALIZE) {
                checkOutputLimit(response);
            }
            writeResponse(output, SUCCESS, response);
            return opcode == Session.CLOSE;
        } catch (Failure e) {
            writeFailure(e.status, e.getMessage());
        } catch (CertificateExpiredException e) {
            writeFailure(Failure.CRYPTO_ERROR, "Certificate has expired");
        } catch (CertificateNotYetValidException e) {
            writeFailure(Failure.CRYPTO_ERROR, "Certificate is not yet valid");
        } catch (NoSuchAlgorithmException e) {
            writeFailure(
                    Failure.UNSUPPORTED,
                    "Algorithm is unavailable in the installed Kalkan Java provider");
        } catch (Exception e) {
            // Provider exception messages may contain user paths or certificate data.
            writeFailure(
                    Failure.CRYPTO_ERROR,
                    "Kalkan Java operation failed: " + e.getClass().getSimpleName());
        } finally {
            for (byte[] field : request) {
                Arrays.fill(field, (byte) 0);
            }
        }
        return false;
    }

    private void checkOutputLimit(byte[][] response) throws Failure {
        for (byte[] field : response) {
            if (field.length > maxOutput) {
                throw new Failure(Failure.OUTPUT_LIMIT, Integer.toString(field.length));
            }
        }
    }

    @Override
    public byte[] fetch(String method, String url, byte[] body) throws Exception {
        validateEndpoint(url);
        writeResponse(output, FETCH_REQUEST, new byte[][] {utf8(method), utf8(url), body});

        int opcode = input.readInt();
        byte[][] response = readRequest(input);
        if (opcode != FETCH_RESPONSE || response.length != 2) {
            throw new Failure(Failure.INVALID_ARGUMENT, "Invalid revocation transport response");
        }
        if (!string(response[0]).equals("ok")) {
            throw new Failure(
                    Failure.CRYPTO_ERROR,
                    "Revocation response could not be fetched: " + string(response[1]));
        }
        if (response[1].length == 0) {
            throw new Failure(Failure.CRYPTO_ERROR, "Revocation server returned an empty response");
        }
        return response[1];
    }

    private static void validateEndpoint(String url) throws Failure {
        if (url.isEmpty()) {
            throw new Failure(
                    Failure.CRYPTO_ERROR, "Certificate has no configured revocation endpoint");
        }

        URI endpoint;
        try {
            endpoint = new URI(url);
        } catch (URISyntaxException e) {
            throw new Failure(Failure.CRYPTO_ERROR, "Invalid certificate revocation URL");
        }

        String scheme = endpoint.getScheme();
        boolean http = "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
        if (!http
                || endpoint.getHost() == null
                || endpoint.getUserInfo() != null
                || endpoint.getFragment() != null) {
            throw new Failure(
                    Failure.CRYPTO_ERROR,
                    "Revocation endpoint must be an absolute HTTP or HTTPS URL without"
                            + " credentials");
        }
    }

    private static byte[][] readRequest(DataInputStream input) throws IOException, Failure {
        int count = input.readInt();
        if (count < 0 || count > MAX_REQUEST_FIELDS) {
            throw new Failure(Failure.INVALID_ARGUMENT, "Invalid request field count");
        }

        byte[][] fields = new byte[count][];
        for (int i = 0; i < count; i++) {
            int size = input.readInt();
            if (size < 0) {
                throw new Failure(Failure.INVALID_ARGUMENT, "Invalid request field length");
            }
            fields[i] = input.readNBytes(size);
            if (fields[i].length != size) {
                throw new EOFException();
            }
        }
        return fields;
    }

    private static void writeResponse(DataOutputStream output, int status, byte[][] fields)
            throws IOException {
        output.writeInt(status);
        output.writeInt(fields.length);
        for (byte[] field : fields) {
            output.writeInt(field.length);
            output.write(field);
        }
        output.flush();
    }

    private void writeFailure(int status, String message) throws IOException {
        writeResponse(output, status, new byte[][] {utf8(message)});
    }

    void initializationFailed() throws IOException {
        writeFailure(Failure.CRYPTO_ERROR, "Kalkan Java provider initialization failed");
    }
}
