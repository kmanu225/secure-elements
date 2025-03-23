package civ.cryptoki;

import java.io.File;

public class Utils {

    /**
     * Set PKCS#11 library path.
     *
     * @return The path of the cryptoki library.
     */
    public static String setupLibrary(String libPath) throws Exception {
        String library;

        if (new File(libPath).exists()) {
            library = libPath;
        } else {
            throw new Exception("Library not found on the plateform.");
        }
        return library;
    }
}
