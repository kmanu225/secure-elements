# PKCS#11 Programs with Maven Support

## Prerequisites

- Java 9 or higher
- Maven (for building the project)
- Cryptographic token and its corresponding PKCS#11 driver/library

## Building the Project

To build the project with Maven:

```sh
mvn clean package
```

The output JAR will be generated in the `target` directory.

## Usage

### Run the predefined Main Class

To execute the main class:

```sh
java -jar pkcs11-1.0.jar
```

### Run a Specific Module

If you want to run a specific module, use the following command:

```sh
java --add-exports jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED -cp jsun-1.0.jar <module> <arguments>
```

See example below:

To get information about the cryptographic token:

```sh
java --add-exports jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED -cp jsun-1.0.jar pkcs11.jsun.GetInfo -info -slot -token 0
```

## Troubleshooting

1. **Class Not Found:** Ensure the `-cp` parameter correctly points to the `jsun-1.0.jar`.
2. **Access Denied Errors:** Ensure the Java version supports `--add-exports` and that the cryptographic token is correctly connected.
3. **PKCS#11 Library Issues:** Verify the token's driver/library is correctly installed and referenced.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
