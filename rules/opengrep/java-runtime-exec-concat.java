// Annotated test file for java-runtime-exec-concat. Deliberately vulnerable: do not run.
import java.io.IOException;

public class RuntimeExecSample {
    public Process ping(String host) throws IOException {
        // ruleid: java-runtime-exec-concat
        return Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    public Process archive(String name) throws IOException {
        Runtime rt = Runtime.getRuntime();
        // ruleid: java-runtime-exec-concat
        return rt.exec(String.format("tar czf %s.tgz %s", name, name));
    }

    public Process pingArgs(String host) throws IOException {
        // ok: java-runtime-exec-concat
        return Runtime.getRuntime().exec(new String[] {"ping", "-c", "1", host});
    }

    public Process constant() throws IOException {
        // ok: java-runtime-exec-concat
        return Runtime.getRuntime().exec("ls -l /tmp");
    }
}
