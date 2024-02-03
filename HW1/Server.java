import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;

public class Server {
  // Start console application

  // Constants section
  private static final String VERSION = "Server 1.0.0";
  private static final String USAGE = """
      USAGE:
        java Server.java <port> [OPTIONS]
        javac Server.java && java Server <port> [OPTIONS]

      EXAMPLE:
        java Server.java 8000

      OPTIONS:
        -h, --help\t Prints help information
        -v, --verison\t Prints verison information

      PARAMETERS:
        port
                                      """;
  private static final String PORT_EXCEPTION = "Port must be an integer (usage java Server.java -h)";
  private static final String[] HELP_OPTION_STRINGS = { "-h", "--help" };
  private static final String[] VERSION_OPTION_STRINGS = { "-v", "--verison" };
  // End of constants section

  private static void printUsage() {
    System.out.print(USAGE);
  }

  private static void printVersion() {
    System.out.println(VERSION);
  }

  private static int getPort(String[] args) {
    if (args.length == 0 || Arrays.asList(HELP_OPTION_STRINGS).contains(args[0])) {
      printUsage();
      System.exit(0);
    } else if (Arrays.asList(VERSION_OPTION_STRINGS).contains(args[0])) {
      printVersion();
      System.exit(0);
    }

    int port = -1;

    try {
      port = Integer.valueOf(args[0]);
    } catch (NumberFormatException e) {
      System.out.println(PORT_EXCEPTION);
      System.exit(0);
    }

    return port;
  }
  // End console application

  private static ServerSocket server;
  private static Socket clientSocket;
  private static BufferedReader in;
  private static BufferedWriter out;

  public static void main(String[] args) {
    int port = getPort(args);

    try {
      server = new ServerSocket(port);
      System.out.println("Server started at " + port);

      clientSocket = server.accept();

      try {
        in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));

        System.out.println(clientSocket.isConnected());
        // while (true) {
        String receivedString = in.readLine();
        out.write("!" + receivedString + "!\n");
        out.flush();
        // }

      } finally {
        in.close();
        out.close();
        clientSocket.close();
      }
    } catch (IOException e) {
      System.err.println(e);
    } finally {
      try {
        server.close();
        System.out.println("Server closed");
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
  }
}
