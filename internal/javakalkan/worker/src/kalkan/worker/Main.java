package kalkan.worker;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;

import java.io.OutputStream;
import java.io.PrintStream;
import java.security.Security;

/** Process entry point. Protocol bytes exclusively own the original stdout. */
public final class Main {
    private Main() {}

    public static void main(String[] args) throws Exception {
        Protocol protocol = new Protocol(System.in, System.out);
        System.setOut(new PrintStream(OutputStream.nullOutputStream()));
        try {
            Security.addProvider(new KalkanProvider());
        } catch (RuntimeException | LinkageError e) {
            protocol.initializationFailed();
            return;
        }
        protocol.serve(new Session(protocol, Boolean.parseBoolean(args[0])));
    }
}
