import java.io.*;
import java.net.Socket;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class Client {
  // Start console application

  // Constants section
  private static final String VERSION = "Client 1.0.0";
  private static final String USAGE = """
      USAGE:
        java Client.java <ip> <port> <n> <m> <q> [OPTIONS]
        or
        javac Client.java && java Client <ip> <port> <n> <m> <q> [OPTIONS]

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
                                      """;
  private static final String PORT_ERROR = "Invalid port (usage java Server.java -h)";
  private static final String PARAMETERS_ERROR = "Invalid parameters (usage java Server.java -h)";
  private static final String[] HELP_OPTION_STRINGS = { "-h", "--help" };
  private static final String[] VERSION_OPTION_STRINGS = { "-v", "--verison" };
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
      System.err.println();
      System.exit(0);
    }

    int[] parameters = new int[3];

    try {
      for (int i = 2; i < args.length; i++) {
        parameters[i - 2] = Integer.valueOf(args[i]);
        if (parameters[i - 2] < 0) {
          throw new NumberFormatException();
        }
      }
    } catch (NumberFormatException e) {
      System.err.println(PARAMETERS_ERROR);
      System.exit(0);
    }

    return parameters;
  }

  // End console application
  private static boolean tcpNoDelay = true;

  private static String ip;
  private static int port;

  private static Socket socket;
  private static BufferedReader in;
  private static BufferedWriter out;

  private static String getRandomString(int len) {
    byte[] array = new byte[len];
    new Random().nextBytes(array);

    return new String(array).replace("\n", " ");
  }

  public static void main(String[] args) {
    int[] parameters = getParameters(args);

    int n = parameters[0];
    int m = parameters[1];
    int q = parameters[2];

    try {
      socket = new Socket(ip, port);
      socket.setTcpNoDelay(tcpNoDelay);

      in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
      out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

      for (int k = 0; k < m; k++) {
        for (int i = 0; i < q; i++) {
          System.out.print("a:");
          // String j = new Scanner(System.in).nextLine();

          out.write("j" + "\n");
          out.flush();

          // out.write(getRandomString(n * k + 8) + "\n");
          // out.flush();

          String response = "", s = "";
          while ((s = in.readLine()) != null) {
            response += s;
          }
          System.out.println(response);

        }
      }
    } catch (IOException e) {
      System.err.println(e);
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
}
