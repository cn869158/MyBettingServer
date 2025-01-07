import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

public class BettingServer {
    private static final int PORT = 8001;
    private static final long SESSION_EXPIRATION_TIME = TimeUnit.MINUTES.toMillis(10);
    private static final Map<Integer, Session> sessions = new ConcurrentHashMap<>();
    private static final ConcurrentMap<Integer, Map<String, Integer>> stakes = new ConcurrentHashMap<>();
    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        BettingServer service = new BettingServer();
        server.createContext("/session", new SessionHandler());
        server.createContext("/stake", new StakeHandler());
        server.createContext("/highstakes", new HighStakesHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port:" + PORT);

        scheduler.scheduleAtFixedRate(service::cleanupExpiredSessions, SESSION_EXPIRATION_TIME, SESSION_EXPIRATION_TIME, TimeUnit.MILLISECONDS);
    }

    private void cleanupExpiredSessions() {
        long currentTime = System.currentTimeMillis();
        sessions.values().removeIf(session -> currentTime - session.getCreationTime() > SESSION_EXPIRATION_TIME);
    }

    private static String getSessionKey(int customerId) {
        return sessions.computeIfAbsent(customerId, key -> new Session(UUID.randomUUID().toString().replaceAll("-", ""))).getSessionKey();
    }

    private static boolean isValidSession(String sessionKey) {
        return sessions.values().stream().anyMatch(session -> session.getSessionKey().equals(sessionKey));
    }

    static class Session {
        private final String sessionKey;
        private final long creationTime;
        private int customerId = 0;

        public Session(String sessionKey) {
            this.sessionKey = sessionKey;
            this.creationTime = System.currentTimeMillis();
            this.customerId = customerId;
        }

        public String getSessionKey() {
            return sessionKey;
        }

        public long getCreationTime() {
            return creationTime;
        }

        public int getCustomerId() {
            return customerId;
        }
    }

    private static class SessionHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                try {
                    String path = exchange.getRequestURI().getPath();
                    int customerId = Integer.parseInt(path.split("/")[2]);
                    String sessionKey = getSessionKey(customerId);
                    System.out.println("customerId:"+customerId + " sessionKey:"+sessionKey);
                    sendResponse(exchange, sessionKey);
                } catch (NumberFormatException | ArrayIndexOutOfBoundsException e) {
                    exchange.sendResponseHeaders(400, 0);
                    exchange.close();
                }
            }
        }

        private void sendResponse(HttpExchange exchange, String response) throws IOException {
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    private static class StakeHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                try {
                    String[] parts = exchange.getRequestURI().getPath().split("/");
                    if (parts.length != 3) throw new IllegalArgumentException();

                    int betOfferId = Integer.parseInt(parts[2]);
                    String query = exchange.getRequestURI().getQuery();
                    if (query == null || !query.startsWith("sessionkey=")) throw new IllegalArgumentException();

                    String sessionKey = query.substring("sessionkey=".length());
                    if (!isValidSession(sessionKey)) {
                        exchange.sendResponseHeaders(401, 0);
                        exchange.close();
                        return;
                    }

                    int stake = Integer.parseInt(new String(exchange.getRequestBody().readAllBytes()));
                    addOrUpdateStake(betOfferId, sessionKey, stake);
                    exchange.sendResponseHeaders(200, 0);
                    exchange.close();
                } catch (IllegalArgumentException e) {
                    exchange.sendResponseHeaders(400, 0);
                    exchange.close();
                }
            }
        }

        private void addOrUpdateStake(int betOfferId, String sessionKey, int stake) {
            stakes.computeIfAbsent(betOfferId, k -> new HashMap<>())
                    .merge(sessionKey, stake, Math::max);
        }
    }

    private static class HighStakesHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                try {
                    String[] parts = exchange.getRequestURI().getPath().split("/");
                    if (parts.length != 3) throw new IllegalArgumentException();

                    int betOfferId = Integer.parseInt(parts[2]);
                    List<String> highStakes = getHighStakes(betOfferId);
                    String response = String.join(",", highStakes);
                    sendResponse(exchange, response);
                } catch (IllegalArgumentException e) {
                    exchange.sendResponseHeaders(400, 0);
                    exchange.close();
                }
            }
        }

        private List<String> getHighStakes(int betOfferId) {
            return stakes.getOrDefault(betOfferId, Collections.emptyMap()).entrySet().stream()
                    .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                    .limit(20)
                    .map(entry -> {
                        int customerId = sessions.entrySet().stream()
                                .filter(sessionEntry -> entry.getKey().equals(sessionEntry.getValue().getSessionKey()))
                                .map(Map.Entry::getKey)
                                .findFirst()
                                .orElse(-1); // Should never be -1 in a valid scenario.
                        return customerId + "=" + entry.getValue();
                    })
                    .collect(Collectors.toList());
        }

        private void sendResponse(HttpExchange exchange, String response) throws IOException {
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }
}
