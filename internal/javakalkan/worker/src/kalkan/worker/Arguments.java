package kalkan.worker;

import java.nio.charset.StandardCharsets;
import java.util.Date;

/** Conversion and validation of the bridge's scalar argument representation. */
final class Arguments {
    private Arguments() {}

    static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    static String string(byte[] data) {
        return new String(data, StandardCharsets.UTF_8);
    }

    static boolean bool(byte[] data) throws Failure {
        return switch (string(data)) {
            case "1" -> true;
            case "0" -> false;
            default -> throw new Failure(Failure.INVALID_ARGUMENT, "Invalid boolean argument");
        };
    }

    static int number(byte[] data) throws Failure {
        try {
            int value = Integer.parseInt(string(data));
            if (value >= 0) {
                return value;
            }
        } catch (NumberFormatException ignored) {
            // Negative and malformed numbers share the same protocol error.
        }
        throw new Failure(Failure.INVALID_ARGUMENT, "Invalid nonnegative integer argument");
    }

    static Date validationTime(byte[] data) throws Failure {
        try {
            long seconds = Long.parseLong(string(data));
            return seconds == 0 ? null : new Date(Math.multiplyExact(seconds, 1000L));
        } catch (NumberFormatException | ArithmeticException e) {
            throw new Failure(Failure.INVALID_ARGUMENT, "Invalid certificate validation time");
        }
    }

    static void count(byte[][] args, int expected) throws Failure {
        if (args.length != expected) {
            throw new Failure(Failure.INVALID_ARGUMENT, "Incorrect operation argument count");
        }
    }
}
