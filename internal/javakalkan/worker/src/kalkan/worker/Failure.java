package kalkan.worker;

/** An expected operation error whose status and safe message cross the bridge. */
final class Failure extends Exception {
    static final int INVALID_ARGUMENT = 1;
    static final int UNSUPPORTED = 2;
    static final int CRYPTO_ERROR = 3;
    static final int OUTPUT_LIMIT = 4;

    final int status;

    Failure(int status, String message) {
        super(message);
        this.status = status;
    }
}
