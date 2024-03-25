import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.*;

public class Main {
    public static void main(String[] args) throws Exception {
        String password = "sha0rm3lul";
        byte[] salt = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);

        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        String key = Base64.getEncoder().encodeToString(keyBytes);

        SecretKeySpec skeySpec = new SecretKeySpec(Base64.getDecoder().decode(key), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

        List<String> headers = new ArrayList<>();
        ///similar, path-urile treburile adaptate pentru fiecare user ce va folosi codul
        Path startDir = Paths.get("C:\\Users\\white\\IdeaProjects\\SSI_2ndProblem\\src\\Original_name");
        Path endDir = Paths.get("C:\\Users\\white\\IdeaProjects\\SSI_2ndProblem\\src\\encoded");
        Path testDir = Paths.get("C:\\Users\\white\\IdeaProjects\\SSI_2ndProblem\\src\\testing");

        Files.walkFileTree(startDir, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                if (!file.getFileName().toString().startsWith(".")) {
                    byte[] headerBytes = Files.readAllBytes(file);
                    String header = new String(headerBytes, 0, 13);
                    StringBuilder sb = new StringBuilder(header);
                    sb.deleteCharAt(header.length() - 1);
                    ///header-ul pentru testarea numelui are lungimea 13
                    ///header-ul pentru hashuire are lungimea 12
                    ///asta se intampla din cauza caracterului \n
                    ///ce nu are voie sa faca parte din string-ul de hashuit
                    String nheader = sb.toString();
                    headers.add(nheader);
                    ///aici ne ocupam de scoaterea headerelor si criptarea pozelor
                    byte[] imageBytes = Arrays.copyOfRange(headerBytes, 13, headerBytes.length);
                    byte[] encryptedImageBytes;
                    try {
                        encryptedImageBytes = cipher.doFinal(imageBytes);
                    } catch (IllegalBlockSizeException | BadPaddingException e) {
                        throw new RuntimeException(e);
                    }
                    Path endFile = endDir.resolve(file.getFileName());
                    Files.write(endFile, encryptedImageBytes);

                    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                    outputStream.write(header.getBytes());
                    outputStream.write(encryptedImageBytes);

                    byte[] combinedBytes = outputStream.toByteArray();
                    Path testFile = testDir.resolve(file.getFileName());
                    Files.write(testFile,combinedBytes);
                }
                return FileVisitResult.CONTINUE;
            }
        });
        FileWriter writer = new FileWriter("C:\\Users\\white\\IdeaProjects\\SSI_2ndProblem\\src\\hashes.txt");
        for (String header : headers) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(header.getBytes());
            byte[] hashBytes = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            writer.write(sb + System.lineSeparator());
        }
        ///scrierea hashurilor obtinute in fisier
        writer.close();
    }
}