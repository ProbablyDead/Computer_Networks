import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

import javafx.util.Pair;

public class Client {
  // Start console application

  // Constants section
  private static final String VERSION = "Client 1.0.0";
  private static final String USAGE = """
      USAGE:
        java Client.java <ip> <port> <n> <m> <q> <tcp-no-delay> [OPTIONS]
        or
        javac Client.java && java Client <ip> <port> <n> <m> <q> <tcp-no-delay> [OPTIONS]

      EXAMPLE:
        java Client.java 127.0.0.1 8000

      OPTIONS:
        -h, --help\t Prints help information
        -v, --verison\t Prints verison information

      PARAMETERS:
        ip
        port
        n\t Array length in bytes
        m\t Number of iterations
        q\t Number of messages
        tcp-no-delay\t Boolean(true/false), def=true
                                      """;
  private static final String PORT_ERROR = "Invalid port (usage java Server.java -h)";
  private static final String PARAMETERS_ERROR = "Invalid parameters (usage java Server.java -h)";
  private static final String[] HELP_OPTION_STRINGS = { "-h", "--help" };
  private static final String[] VERSION_OPTION_STRINGS = { "-v", "--verison" };
  private static final String FILE_NAME = "results.txt";
  private static final String FILE_PATH = "./local/";
  // End of constants section

  private static void printUsage() {
    System.out.print(USAGE);
  }

  private static void printVersion() {
    System.out.println(VERSION);
  }

  private static int[] getParameters(String[] args) {
    if (args.length < 5 || Arrays.asList(HELP_OPTION_STRINGS).contains(args[0])) {
      printUsage();
      System.exit(0);
    } else if (Arrays.asList(VERSION_OPTION_STRINGS).contains(args[0])) {
      printVersion();
      System.exit(0);
    }

    ip = args[0];
    try {
      port = Integer.valueOf(args[1]);
    } catch (NumberFormatException e) {
      System.err.println(PORT_ERROR);
      System.exit(0);
    }

    int[] parameters = new int[3];

    try {
      for (int i = 2; i < args.length; i++) {
        if ((args[i].equals("true") || args[i].equals("false")) && i == 5) {
          tcpNoDelay = args[i].equals("true");
        } else if (i <= 4) {
          parameters[i - 2] = Integer.valueOf(args[i]);
          if (parameters[i - 2] < 0) {
            throw new NumberFormatException();
          }
        }
      }
    } catch (NumberFormatException e) {
      System.err.println(PARAMETERS_ERROR);
      System.exit(0);
    }

    return parameters;
  }

  private static void printProgressbar(float percentage) {
    int width = 50;

    System.out.print("\u001b[1F");
    System.out.flush();
    System.out.print("[");

    int i = 0;
    for (; i < (int) (percentage * width); i++) {
      System.out.print("▮");
    }
    for (; i < width; i++) {
      System.out.print(" ");
    }
    System.out.print("]\t");
    System.out.println(String.format("\t%.2f", percentage * 100) + "%");
  }

  // End console application
  private static boolean tcpNoDelay = true;

  private static String ip;
  private static int port;

  private static Socket socket;
  private static BufferedReader in;
  private static OutputStream out;

  private static byte[] getRandomBytes(int len) {
    byte[] array = new byte[len + 4], lenBytes = ByteBuffer.allocate(4).putInt(len).array();

    new Random().nextBytes(array);
    for (int i = 0; i < 4; i++) {
      array[i] = lenBytes[i];
    }

    return array;
  }

  public static void main(String[] args) {
    int[] parameters = getParameters(args);

    System.out.println();

    int n = parameters[0];
    int m = parameters[1];
    int q = parameters[2];

    try {
      socket = new Socket(ip, port);
      socket.setTcpNoDelay(tcpNoDelay);

      in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
      out = socket.getOutputStream();

      ArrayList<Pair<Integer, Long>> result = new ArrayList<>(m);

      float maxIterCount = m * q, curIter = 1;

      for (int k = 0; k < m; k++) {
        long average = 0;
        int len = n * k + 8;

        for (int i = 0; i < q; i++) {
          out.write(getRandomBytes(len));
          out.flush();

          long start = System.nanoTime();

          in.readLine();

          average += (System.nanoTime() - start);

          printProgressbar(curIter++ / maxIterCount);
        }

        average /= q;

        result.add(k, new Pair<>(len, average));
      }

      writeResultsToFile(result, parameters);

    } catch (IOException e) {
      System.err.println("No server evoked");
      System.exit(0);
    } finally {
      try {
        in.close();
        out.close();
        socket.close();
        System.out.println("Socket closed");
      } catch (IOException e) {
        System.err.println(e);
      } catch (NullPointerException e) {
        System.err.println(e);
      }
    }
  }

  private static void writeResultsToFile(ArrayList<Pair<Integer, Long>> result, int[] parameters) {
    String parametersString = parameters[0] + "_" + parameters[1]
        + "_" + parameters[2] + "_" + tcpNoDelay + "_";
    String fileName = FILE_PATH + parametersString + FILE_NAME;
    File file = new File(fileName);

    try {
      FileWriter writer = new FileWriter(file);

      String resultString = "Bytes\tTime(ns)\n";

      for (Pair<Integer, Long> res : result) {
        resultString += res.getKey() + "\t" + res.getValue() + "\n";
      }

      writer.write(resultString);
      writer.close();
    } catch (IOException e) {
      System.out.println("Error while writing to a file");
    }

  }
}
