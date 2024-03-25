import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.io.*;
///Problema 1
public class Main {

    ///lista de hashuri
    static List<String> hashValues = Arrays.asList(
            "602a4a8fff652291fdc0e049e3900dae608af64e5e4d2c5d4332603c9938171d",
            "f40e838809ddaa770428a4b2adc1fff0c38a84abe496940d534af1232c2467d5",
            "aa105295e25e11c8c42e4393c008428d965d42c6cb1b906e30be99f94f473bb5",
            "70f87d0b880efcdbe159011126db397a1231966991ae9252b278623aeb9c0450",
            "77a39d581d3d469084686c90ba08a5fb6ce621a552155730019f6c02cb4c0cb6",
            "456ae6a020aa2d54c0c00a71d63033f6c7ca6cbc1424507668cf54b80325dc01",
            "bd0fd461d87fba0d5e61bed6a399acdfc92b12769f9b3178f9752e30f1aeb81d",
            "372df01b994c2b14969592fd2e78d27e7ee472a07c7ac3dfdf41d345b2f8e305"
    );

    ///functie de sha256
    private static String sha256(String text) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();

        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }

        return hexString.toString();
    }
    public static void main(String[] args) {
        List<String> headers = new ArrayList<>();
        ///aplicare brute-force pentru detectarea unui posibil header
        for (int x = 0; x < 650; x++) {
            for (int y = 0; y < 650; y++) {
                String possibleHeader = String.format("P6 %d %d 255", x, y);
                String hash;
                try {
                    hash = sha256(possibleHeader);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

                if (hashValues.contains(hash)) {
                    headers.add(possibleHeader);
                }
            }
        }
        //afisarea headerelor complete
        System.out.println(headers);

        ///punem perechile de width si height pt fiecare header
        ///intr-un pair manual
        List<Pair<Integer, Integer>> xyPairs = new ArrayList<>();
        for (String h : headers) {
            String[] parts = h.split(" ");
            xyPairs.add(new Pair<>(Integer.parseInt(parts[1]), Integer.parseInt(parts[2])));
        }

        ///aici trebuie pus absolute path-ul pe dispozitivul unde este rulat proiectul si unde se afla fisierul
        File folder = new File("C:\\Users\\white\\IdeaProjects\\SSI_Project\\src\\encrypted_files");

        for(File file: Objects.requireNonNull(folder.listFiles())) {
            ///try pentru lucrul cu fisiere in folder
            if(!file.isDirectory()) {
                try {
                    byte[] ciphertext = Files.readAllBytes(file.toPath());
                    for (int pad = 0; pad < 16; pad++) {
                        //impartim la 3 pt ca suntem pe RGB(ne sppune P6 din header) si obtinem
                        //dimensiunea imaginii
                        //putem avea un padding pe poza, pt ca folosim AES ECB
                        double dim = (ciphertext.length - pad) / 3.0;

                        for (Pair<Integer, Integer> xy : xyPairs) {
                            if (dim == xy.getKey() * xy.getValue()) {

                                int x = xy.getKey(), y = xy.getValue();
                                String x_string = Integer.toString(x);
                                String y_string = Integer.toString(y);
                                String desired = "P6\n" + x_string + " " + y_string + "\n255\n";
                                byte[] bytes = desired.getBytes(StandardCharsets.UTF_8);
                                ///pana aici este totul corect

                                try {
                                    byte[] existingContent = Files.readAllBytes(file.toPath());

                                    byte[] combinedContent = new byte[existingContent.length + bytes.length];
                                    System.arraycopy(bytes, 0, combinedContent, 0, bytes.length);
                                    System.arraycopy(existingContent, 0, combinedContent, bytes.length, existingContent.length);

                                    Files.write(file.toPath(), combinedContent);
                                } catch (IOException e) {
                                    e.printStackTrace();
                                }
                                break;
                            }
                        }
                    }

                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }
        ///Concluzie: din fisiere obtii mesajul codificat: "heart"LoveYou
        ///randul 84 face cumva endline doar la 2 din fisiere
        ///asa ca am fost nevoie sa hardcodez celelalte 6
        ///dand enter de fiecare data dupa 255
    }
}