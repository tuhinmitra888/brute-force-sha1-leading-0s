package org.example;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class KnockKnockClient {
    private static boolean runExecutorService = true;
    private static String authData;
    private static int difficulty;
    private static PrintWriter out = null;
    private static ExecutorService executorService = null;
    private static long startTimeMilliSecond = System.currentTimeMillis();

    public static void main(String[] args) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        String CERT_PASSWORD = "Foo_Cert_Password";
        String host = "Foo_Host_Ip_Address";
        int port = 1234; //Port number to connect to

        KeyStore identityKeyStore = KeyStore.getInstance("jks");
        FileInputStream identityKeyStoreFile = new FileInputStream("foo.jks");
        identityKeyStore.load(identityKeyStoreFile, CERT_PASSWORD.toCharArray());

        SSLSocket socket = null;
        BufferedReader in = null;

        try {

            SSLSocketFactory factory;
            SSLContext ctx;
            KeyManagerFactory kmf;
            KeyStore ks;
            char[] passphrase = CERT_PASSWORD.toCharArray();

            ctx = SSLContext.getInstance("TLS");
            kmf = KeyManagerFactory.getInstance("SunX509");
            ks = KeyStore.getInstance("JKS");

            ks.load(new FileInputStream("foo.jks"), passphrase);

            kmf.init(ks, passphrase);
            ctx.init(kmf.getKeyManagers(), null, null);
            factory = ctx.getSocketFactory();


            socket = (SSLSocket) factory.createSocket(host, port);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);
            boolean breakLoop = false;

            while (true) {

                    String inputLine = in.readLine();
                    String[] commands = inputLine.split(" ");
                    System.out.println("Server: " + commands[0]);

                    switch (commands[0]) {
                        case "HELO":
                            out.println("Foo");
                            break;

                        case "ERROR":
                            System.out.println("ERROR: " + StringUtils.join(Arrays.copyOfRange(commands, 1, commands.length), " "));
                            breakLoop = true;
                            break;

                        case "POW":
                            int coreCount = Runtime.getRuntime().availableProcessors();
                            executorService = Executors.newFixedThreadPool(coreCount);

                            authData = commands[1];
                            difficulty = Integer.parseInt(commands[2]);

                            while (runExecutorService) {
                                executorService.execute(new Runner());
                            }
                            break;

                        case "END":
                            out.println("OK");
                            breakLoop = true;
                            break;

                        case "NAME":
                            out.println(DigestUtils.sha1Hex(authData + commands[1]) + " " + "Firstname Lastname");
                            break;

                        case "MAILNUM":
                            out.println(DigestUtils.sha1Hex(authData + commands[1]) + " " + "2");
                            break;

                        case "MAIL1":
                            out.println(DigestUtils.sha1Hex(authData + commands[1]) + " " + "mail1@example.com");
                            break;

                        case "MAIL2":
                            out.println(DigestUtils.sha1Hex(authData + commands[1]) + " " + "mail2@example.com");
                            break;

                        case "SKYPE":
                            out.println(DigestUtils.sha1Hex(authData + commands[1]) + " " + "skype.id");
                            break;

                        case "BIRTHDATE":
                            out.println(DigestUtils.sha1Hex(authData + commands[1]) + " " + "01.01.2021");
                            break;

                        case "COUNTRY":
                            out.println(DigestUtils.sha1Hex(authData + commands[1]) + " " + "Country");
                            break;

                        case "ADDRNUM":
                            out.println(DigestUtils.sha1Hex(authData + commands[1]) + " " + "2");
                            break;

                        case "ADDRLINE1":
                            out.println(DigestUtils.sha1Hex(authData + commands[1]) + " " + "AddressLine 1");
                            break;

                        case "ADDRLINE2":
                            out.println(DigestUtils.sha1Hex(authData + commands[1]) + " " + "AddressLine 2");
                            break;

                        default:
                            System.out.println("Unknown command");
                            breakLoop = true;
                            break;
                    }
                    if (breakLoop) {
                        break;
                    }
                }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            in.close();
            out.close();
            socket.close();
            executorService.shutdownNow();
            long endTimeMilliSecond = System.currentTimeMillis();
            System.out.println("Time Taken: "+(((endTimeMilliSecond - startTimeMilliSecond) * .0001)/60) + " minutes");
        }
    }

    static class Runner implements Runnable {
        public synchronized void run() {
            if(runExecutorService) {
                String ckSumInHex;
                StringBuilder stringBuilder = new StringBuilder();
                String suffix = RandomStringUtils.randomAlphanumeric(5);

                stringBuilder.append(authData).append(suffix);
                ckSumInHex = DigestUtils.sha1Hex(stringBuilder.toString());

                Pattern p = Pattern.compile("^0{" + difficulty + "}");
                Matcher m = p.matcher(ckSumInHex);

                if (m.find()) {
                    System.out.println("Checksum matched - suffix: " + suffix + " authData: " + authData + " ckSumInHex: " + ckSumInHex);
                    out.println(suffix);
                    runExecutorService = false;
                }
            }
        }
    }
}

