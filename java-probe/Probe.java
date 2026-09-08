import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Разведка перед переносом монитора на игровой хостинг.
 *
 * Панель запускает `java -jar server.jar`, поэтому вместо ядра Minecraft сюда
 * кладётся этот класс. Он выясняет три вещи, без которых монитор не поедет:
 * есть ли исходящий интернет, можно ли скачать и ЗАПУСТИТЬ посторонний
 * бинарник (нужен Xray для узлов подписки) и не гасит ли панель процесс,
 * который ничего не делает.
 */
public class Probe {

    static final HttpClient HTTP = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    public static void main(String[] args) throws Exception {
        say("=== разведка окружения ===");
        say("java: " + System.getProperty("java.version")
                + " | ос: " + System.getProperty("os.name")
                + " " + System.getProperty("os.arch"));
        say("каталог: " + new File(".").getAbsolutePath());
        say("памяти доступно: " + Runtime.getRuntime().maxMemory() / 1048576 + " МБ");

        File shell = new File("/bin/sh");
        say("оболочка /bin/sh: " + (shell.exists() ? "есть" : "нет"));

        say("");
        say("--- 1. исходящий интернет");
        try {
            say("ответ ipinfo: " + get("https://ipinfo.io/json").replaceAll("\\s+", " "));
        } catch (Exception e) {
            say("ИНТЕРНЕТА НЕТ: " + e);
            heartbeat();
            return;
        }

        say("");
        say("--- 2. загрузка и запуск постороннего бинарника");
        Path xray = Path.of("xray");
        try {
            byte[] zip = getBytes(
                    "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip");
            say("архив Xray скачан: " + zip.length / 1024 + " КБ");
            unzipEntry(zip, "xray", xray);
            say("распакован: " + Files.size(xray) / 1024 + " КБ");

            boolean executable = xray.toFile().setExecutable(true);
            say("права на запуск проставлены: " + executable);

            Process p = new ProcessBuilder("./xray", "version")
                    .redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor();
            say("запуск Xray: код " + p.exitValue());
            say("вывод: " + (out.isEmpty() ? "(пусто)" : out.lines().findFirst().orElse("")));
        } catch (Exception e) {
            say("ЗАПУСК БИНАРНИКА НЕ ВЫШЕЛ: " + e);
        }

        say("");
        say("--- 3. связь с Telegram");
        try {
            String me = get("https://api.telegram.org/bot" + System.getenv("TG_TOKEN") + "/getMe");
            say("getMe: " + me.replaceAll("\\s+", " "));
        } catch (Exception e) {
            say("Telegram недоступен (или не задан TG_TOKEN): " + e);
        }

        heartbeat();
    }

    /** Панель может гасить простаивающий сервер — смотрим, доживёт ли процесс. */
    static void heartbeat() throws InterruptedException {
        say("");
        say("=== разведка закончена, дальше просто живу и отмечаюсь раз в минуту ===");
        for (int i = 1; ; i++) {
            Thread.sleep(60_000);
            say("жив, минута " + i);
        }
    }

    static void say(String msg) {
        System.out.println("[монитор] " + msg);
        System.out.flush();
    }

    static String get(String url) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .header("user-agent", "probe/1.0").build();
        return HTTP.send(req, HttpResponse.BodyHandlers.ofString()).body();
    }

    static byte[] getBytes(String url) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .header("user-agent", "probe/1.0").build();
        return HTTP.send(req, HttpResponse.BodyHandlers.ofByteArray()).body();
    }

    static void unzipEntry(byte[] zip, String name, Path target) throws Exception {
        try (ZipInputStream zis = new ZipInputStream(new java.io.ByteArrayInputStream(zip))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().equals(name)) {
                    Files.copy(zis, target, StandardCopyOption.REPLACE_EXISTING);
                    return;
                }
            }
        }
        throw new IllegalStateException("в архиве нет файла " + name);
    }
}
