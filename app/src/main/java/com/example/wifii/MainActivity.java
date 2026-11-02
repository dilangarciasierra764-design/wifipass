package com.example.wifii;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MainActivity extends Activity {

    private static final String[] FIXED = {
        "/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml",
        "/data/misc/wifi/WifiConfigStore.xml",
        "/data/misc/wifi/wpa_supplicant.conf"
    };

    private TextView tvStatus;
    private TextView tvResults;
    private ScrollView scrollView;
    private String lastResult = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tvStatus = findViewById(R.id.tvStatus);
        tvResults = findViewById(R.id.tvResults);
        scrollView = findViewById(R.id.scrollView);
        tvResults.setTextIsSelectable(true);

        Button scan = findViewById(R.id.btnScan);
        Button copy = findViewById(R.id.btnCopy);
        Button share = findViewById(R.id.btnShare);

        scan.setOnClickListener(v -> {
            scan.setEnabled(false);
            tvResults.setText("");
            tvStatus.setText("Analizando…");
            tvStatus.setTextColor(0xFF666666);
            new Thread(() -> {
                work();
                runOnUiThread(() -> scan.setEnabled(true));
            }).start();
        });

        copy.setOnClickListener(v -> {
            if (lastResult.isEmpty()) { toast("Nada que copiar"); return; }
            ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("wifi", lastResult));
            toast("Copiado");
        });

        share.setOnClickListener(v -> {
            if (lastResult.isEmpty()) { toast("Nada que compartir"); return; }
            Intent i = new Intent(Intent.ACTION_SEND);
            i.setType("text/plain");
            i.putExtra(Intent.EXTRA_TEXT, lastResult);
            startActivity(Intent.createChooser(i, "Compartir"));
        });

        new Thread(this::work).start();
    }

    private void work() {
        String out = execSu(buildScript());

        if (out == null) {
            fail("Estado: su no disponible", "Instala Magisk/SuperSU y concede root.");
            return;
        }
        if (!out.contains("uid=0")) {
            fail("Estado: permiso root denegado",
                 "Acepta el diálogo de root con la app abierta.\n\nSalida:\n" + out);
            return;
        }
        if (!out.contains("###DONE")) {
            fail("Estado: tiempo agotado",
                 "El shell root no respondió en 25 s. Revisa Magisk.\n\nSalida parcial:\n" + out);
            return;
        }
        if (!out.contains("###FILE:")) {
            fail("Estado: root OK, sin archivos accesibles",
                 "Ninguna ruta es legible. Desactiva el DenyList de Magisk para esta app.\n\nSalida:\n" + out);
            return;
        }

        String parsed = parse(out);
        runOnUiThread(() -> {
            tvStatus.setText("Estado: ROOT OK");
            tvStatus.setTextColor(0xFF00AA00);
            tvResults.setText(parsed);
            lastResult = parsed;
            scrollView.scrollTo(0, 0);
        });
    }

    private String buildScript() {
        StringBuilder sb = new StringBuilder();
        sb.append("echo \"###ID\"\n");
        sb.append("id 2>&1\n");
        sb.append("echo \"###FIND\"\n");
        sb.append("LIST=$(find /data/misc /data/vendor /data/apex -maxdepth 6 ");
        sb.append("\\( -name 'WifiConfigStore.xml' -o -name 'wpa_supplicant.conf' \\) 2>/dev/null)\n");
        for (String f : FIXED) {
            sb.append("[ -e \"").append(f).append("\" ] && LIST=\"$LIST ").append(f).append("\"\n");
        }
        sb.append("echo \"$LIST\"\n");
        sb.append("echo \"###DUMP\"\n");
        sb.append("for f in $LIST; do\n");
        sb.append("  [ -r \"$f\" ] || continue\n");
        sb.append("  echo \"###FILE:$f\"\n");
        sb.append("  cat \"$f\" 2>&1\n");
        sb.append("  echo \"###END\"\n");
        sb.append("done\n");
        sb.append("echo \"###DONE\"\n");
        return sb.toString();
    }

    private String execSu(String script) {
        Process p = null;
        try {
            p = Runtime.getRuntime().exec(new String[]{"su", "-c", script});
            final Process proc = p;

            Thread watchdog = new Thread(() -> {
                try {
                    if (!proc.waitFor(25, TimeUnit.SECONDS)) proc.destroy();
                } catch (Exception ignored) { }
            });
            watchdog.setDaemon(true);
            watchdog.start();

            StringBuilder sb = new StringBuilder();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = r.readLine()) != null) sb.append(line).append('\n');
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        } finally {
            if (p != null) p.destroy();
        }
    }

    private void fail(String status, String detail) {
        runOnUiThread(() -> {
            tvStatus.setText(status);
            tvStatus.setTextColor(0xFFCC0000);
            tvResults.setText(detail);
            lastResult = detail;
        });
    }

    private void toast(String m) {
        runOnUiThread(() -> Toast.makeText(this, m, Toast.LENGTH_SHORT).show());
    }

    private static final Pattern NET  = Pattern.compile("<WifiConfiguration>(.*?)</WifiConfiguration>", Pattern.DOTALL);
    private static final Pattern SSID = Pattern.compile("<string name=\"SSID\">(.*?)</string>", Pattern.DOTALL);
    private static final Pattern PSK  = Pattern.compile("<string name=\"PreSharedKey\">(.*?)</string>", Pattern.DOTALL);
    private static final Pattern NULLPSK = Pattern.compile("<null name=\"PreSharedKey\"");
    private static final Pattern C_SSID = Pattern.compile("ssid=\"(.*?)\"");
    private static final Pattern C_PSK  = Pattern.compile("psk=\"(.*?)\"");

    private String parse(String raw) {
        StringBuilder out = new StringBuilder();
        String[] parts = raw.split("###FILE:");
        int count = 0;

        for (int i = 1; i < parts.length; i++) {
            String part = parts[i];
            int nl = part.indexOf('\n');
            if (nl < 0) continue;
            String path = part.substring(0, nl).trim();

            int end = part.indexOf("###END");
            String body = end < 0 ? part.substring(nl + 1) : part.substring(nl + 1, end);

            StringBuilder block = new StringBuilder();
            if (path.endsWith(".xml")) {
                Matcher m = NET.matcher(body);
                while (m.find()) {
                    String inner = m.group(1);
                    String ssid = first(SSID, inner);
                    if (ssid == null) continue;
                    String psk = first(PSK, inner);
                    if (psk == null && NULLPSK.matcher(inner).find()) psk = "(red abierta)";
                    block.append("SSID: ").append(ssid).append('\n');
                    block.append("CLAVE: ").append(psk == null ? "(no legible)" : psk).append("\n\n");
                }
            } else {
                String ssid = null, psk = null;
                for (String l : body.split("\n")) {
                    Matcher a = C_SSID.matcher(l);
                    Matcher b = C_PSK.matcher(l);
                    if (a.find() && ssid == null) ssid = a.group(1);
                    if (b.find() && psk == null) psk = b.group(1);
                }
                if (ssid != null) {
                    block.append("SSID: ").append(ssid).append('\n');
                    block.append("CLAVE: ").append(psk == null ? "(red abierta)" : psk).append("\n\n");
                }
            }

            if (block.length() > 0) {
                out.append("── ").append(path).append(" ──\n");
                out.append(block);
                count++;
            }
        }

        return count == 0 ? "Se encontraron archivos pero ninguna red parseable." : out.toString();
    }

    private static String first(Pattern p, String src) {
        Matcher m = p.matcher(src);
        if (!m.find()) return null;
        String v = m.group(1).trim()
                .replace("&quot;", "\"").replace("&apos;", "'")
                .replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&");
        if (v.startsWith("\"")) v = v.substring(1);
        if (v.endsWith("\"")) v = v.substring(0, v.length() - 1);
        return (v.isEmpty() || v.equals("null")) ? null : v;
    }
}
