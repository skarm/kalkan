import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

/** Compiles and starts the worker in the JDK 17 source-launcher JVM. */
public final class Bootstrap {
    private Bootstrap() {}

    public static void main(String[] args) throws Exception {
        Path directory = Path.of(args[0]);
        Path classes = Files.createDirectory(directory.resolve("classes"));
        if (compileWorker(directory.resolve("src/kalkan"), classes)) {
            runWorker(classes, args[1]);
        }
    }

    private static boolean compileWorker(Path sourceDirectory, Path classes) throws IOException {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            fail("A full JDK 17 or later is required");
            return false;
        }

        List<File> sources;
        try (var paths = Files.walk(sourceDirectory)) {
            sources =
                    paths.filter(path -> path.toString().endsWith(".java"))
                            .sorted()
                            .map(Path::toFile)
                            .toList();
        }

        try (StandardJavaFileManager files =
                compiler.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {
            List<String> options =
                    List.of(
                            "--release",
                            "17",
                            "-proc:none",
                            "-implicit:none",
                            "-classpath",
                            System.getProperty("java.class.path"),
                            "-d",
                            classes.toString());
            boolean compiled =
                    compiler.getTask(
                                    null,
                                    files,
                                    null,
                                    options,
                                    null,
                                    files.getJavaFileObjectsFromFiles(sources))
                            .call();
            if (!compiled) {
                fail(
                        "Kalkan Java worker compilation failed; check the configured provider and"
                                + " XML JARs");
            }
            return compiled;
        }
    }

    private static void runWorker(Path classes, String xmlEnabled) throws Exception {
        URL[] classpath = {classes.toUri().toURL()};
        try (URLClassLoader loader =
                new URLClassLoader(classpath, ClassLoader.getSystemClassLoader())) {
            Thread.currentThread().setContextClassLoader(loader);
            try {
                loader.loadClass("kalkan.worker.Main")
                        .getMethod("main", String[].class)
                        .invoke(null, (Object) new String[] {xmlEnabled});
            } catch (InvocationTargetException e) {
                Throwable cause = e.getCause();
                if (cause instanceof Exception exception) {
                    throw exception;
                }
                if (cause instanceof Error error) {
                    throw error;
                }
                throw e;
            }
        }
    }

    private static void fail(String message) throws IOException {
        byte[] encoded = message.getBytes(StandardCharsets.UTF_8);
        DataOutputStream output = new DataOutputStream(System.out);
        output.writeInt(3); // Protocol crypto-error status; worker classes are not loaded yet.
        output.writeInt(1);
        output.writeInt(encoded.length);
        output.write(encoded);
        output.flush();
    }
}
