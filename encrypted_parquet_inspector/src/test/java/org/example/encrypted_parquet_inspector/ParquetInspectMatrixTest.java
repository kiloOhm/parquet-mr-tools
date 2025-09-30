package org.example.encrypted_parquet_inspector;

import org.example.parquet_sample_generator.ParquetSampleGenerator;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * Runs org.example.ParquetInspect in a separate JVM (so System.exit inside
 * main
 * doesn't kill the JUnit JVM) and validates encryption metadata for every
 * generated sample produced by ParquetGenerateAll.
 */
public class ParquetInspectMatrixTest {

  private static final ObjectMapper OM = new ObjectMapper();

  // Adjust if needed
private static final String OUT_DIR = "./samples";
private static final Path OUT_PATH   = Paths.get(OUT_DIR).toAbsolutePath().normalize();
  private static final String USER_KEY = "testBaseKey";
  private static final String AAD_PREFIX = "mr-suite"; // your generator used this

  private static final List<String> COLS = List.of("name", "age", "salary", "ssn");
  private static final List<String> PARTIAL_FOOTER_KEY_COLS = List.of("name", "age");

  @BeforeAll
  static void checkOutDir() {
    if(!OUT_PATH.toFile().exists()) {
      // generate samples if missing
      try {
        // Usage: parquet-generate-all <outDir> <baseKeyUtf8> [--rows=N] [--aadPrefix=STR]
        ParquetSampleGenerator.main(new String[] { OUT_PATH.toString(), USER_KEY, "--rows=100", "--aadPrefix=" + AAD_PREFIX });
      } catch (Exception e) {
        fail("Failed to generate samples in " + OUT_PATH + ": " + e);
      }
    }

    assertTrue(OUT_PATH.toFile().exists(), "No sample dir " + OUT_PATH);
  }

  // ---------------- parameter matrix ----------------

  static List<Object[]> cases() {
    // exactly the list you provided
    String[] samples = new String[] {
        "algo=gcm_ctr,mode=EF,aad=none,partial=Y,keymeta=N_file-16.parquet",
        "algo=gcm_ctr,mode=EF,aad=none,partial=Y,keymeta=N_file-32.parquet",
        "algo=gcm_ctr,mode=EF,aad=none,partial=Y,keymeta=Y_file-16.parquet",
        "algo=gcm_ctr,mode=EF,aad=none,partial=Y,keymeta=Y_file-32.parquet",
        "algo=gcm_ctr,mode=EF,aad=none,uniform=Y_file-16.parquet",
        "algo=gcm_ctr,mode=EF,aad=none,uniform=Y_file-32.parquet",
        "algo=gcm_ctr,mode=EF,aad=stored,partial=Y,keymeta=N_file-16.parquet",
        "algo=gcm_ctr,mode=EF,aad=stored,partial=Y,keymeta=N_file-32.parquet",
        "algo=gcm_ctr,mode=EF,aad=stored,partial=Y,keymeta=Y_file-16.parquet",
        "algo=gcm_ctr,mode=EF,aad=stored,partial=Y,keymeta=Y_file-32.parquet",
        "algo=gcm_ctr,mode=EF,aad=stored,uniform=Y_file-16.parquet",
        "algo=gcm_ctr,mode=EF,aad=stored,uniform=Y_file-32.parquet",
        "algo=gcm_ctr,mode=EF,aad=supply,partial=Y,keymeta=N_file-16.parquet",
        "algo=gcm_ctr,mode=EF,aad=supply,partial=Y,keymeta=N_file-32.parquet",
        "algo=gcm_ctr,mode=EF,aad=supply,partial=Y,keymeta=Y_file-16.parquet",
        "algo=gcm_ctr,mode=EF,aad=supply,partial=Y,keymeta=Y_file-32.parquet",
        "algo=gcm_ctr,mode=EF,aad=supply,uniform=Y_file-16.parquet",
        "algo=gcm_ctr,mode=EF,aad=supply,uniform=Y_file-32.parquet",
        "algo=gcm_ctr,mode=PF,aad=none,partial=Y,keymeta=N_file-16.parquet",
        "algo=gcm_ctr,mode=PF,aad=none,partial=Y,keymeta=N_file-32.parquet",
        "algo=gcm_ctr,mode=PF,aad=none,partial=Y,keymeta=Y_file-16.parquet",
        "algo=gcm_ctr,mode=PF,aad=none,partial=Y,keymeta=Y_file-32.parquet",
        "algo=gcm_ctr,mode=PF,aad=none,uniform=Y_file-16.parquet",
        "algo=gcm_ctr,mode=PF,aad=none,uniform=Y_file-32.parquet",
        "algo=gcm_ctr,mode=PF,aad=stored,partial=Y,keymeta=N_file-16.parquet",
        "algo=gcm_ctr,mode=PF,aad=stored,partial=Y,keymeta=N_file-32.parquet",
        "algo=gcm_ctr,mode=PF,aad=stored,partial=Y,keymeta=Y_file-16.parquet",
        "algo=gcm_ctr,mode=PF,aad=stored,partial=Y,keymeta=Y_file-32.parquet",
        "algo=gcm_ctr,mode=PF,aad=stored,uniform=Y_file-16.parquet",
        "algo=gcm_ctr,mode=PF,aad=stored,uniform=Y_file-32.parquet",
        "algo=gcm_ctr,mode=PF,aad=supply,partial=Y,keymeta=N_file-16.parquet",
        "algo=gcm_ctr,mode=PF,aad=supply,partial=Y,keymeta=N_file-32.parquet",
        "algo=gcm_ctr,mode=PF,aad=supply,partial=Y,keymeta=Y_file-16.parquet",
        "algo=gcm_ctr,mode=PF,aad=supply,partial=Y,keymeta=Y_file-32.parquet",
        "algo=gcm_ctr,mode=PF,aad=supply,uniform=Y_file-16.parquet",
        "algo=gcm_ctr,mode=PF,aad=supply,uniform=Y_file-32.parquet",
        "algo=gcm,mode=EF,aad=none,partial=Y,keymeta=N_file-16.parquet",
        "algo=gcm,mode=EF,aad=none,partial=Y,keymeta=N_file-32.parquet",
        "algo=gcm,mode=EF,aad=none,partial=Y,keymeta=Y_file-16.parquet",
        "algo=gcm,mode=EF,aad=none,partial=Y,keymeta=Y_file-32.parquet",
        "algo=gcm,mode=EF,aad=none,uniform=Y_file-16.parquet",
        "algo=gcm,mode=EF,aad=none,uniform=Y_file-32.parquet",
        "algo=gcm,mode=EF,aad=stored,partial=Y,keymeta=N_file-16.parquet",
        "algo=gcm,mode=EF,aad=stored,partial=Y,keymeta=N_file-32.parquet",
        "algo=gcm,mode=EF,aad=stored,partial=Y,keymeta=Y_file-16.parquet",
        "algo=gcm,mode=EF,aad=stored,partial=Y,keymeta=Y_file-32.parquet",
        "algo=gcm,mode=EF,aad=stored,uniform=Y_file-16.parquet",
        "algo=gcm,mode=EF,aad=stored,uniform=Y_file-32.parquet",
        "algo=gcm,mode=EF,aad=supply,partial=Y,keymeta=N_file-16.parquet",
        "algo=gcm,mode=EF,aad=supply,partial=Y,keymeta=N_file-32.parquet",
        "algo=gcm,mode=EF,aad=supply,partial=Y,keymeta=Y_file-16.parquet",
        "algo=gcm,mode=EF,aad=supply,partial=Y,keymeta=Y_file-32.parquet",
        "algo=gcm,mode=EF,aad=supply,uniform=Y_file-16.parquet",
        "algo=gcm,mode=EF,aad=supply,uniform=Y_file-32.parquet",
        "algo=gcm,mode=PF,aad=none,partial=Y,keymeta=N_file-16.parquet",
        "algo=gcm,mode=PF,aad=none,partial=Y,keymeta=N_file-32.parquet",
        "algo=gcm,mode=PF,aad=none,partial=Y,keymeta=Y_file-16.parquet",
        "algo=gcm,mode=PF,aad=none,partial=Y,keymeta=Y_file-32.parquet",
        "algo=gcm,mode=PF,aad=none,uniform=Y_file-16.parquet",
        "algo=gcm,mode=PF,aad=none,uniform=Y_file-32.parquet",
        "algo=gcm,mode=PF,aad=stored,partial=Y,keymeta=N_file-16.parquet",
        "algo=gcm,mode=PF,aad=stored,partial=Y,keymeta=N_file-32.parquet",
        "algo=gcm,mode=PF,aad=stored,partial=Y,keymeta=Y_file-16.parquet",
        "algo=gcm,mode=PF,aad=stored,partial=Y,keymeta=Y_file-32.parquet",
        "algo=gcm,mode=PF,aad=stored,uniform=Y_file-16.parquet",
        "algo=gcm,mode=PF,aad=stored,uniform=Y_file-32.parquet",
        "algo=gcm,mode=PF,aad=supply,partial=Y,keymeta=N_file-16.parquet",
        "algo=gcm,mode=PF,aad=supply,partial=Y,keymeta=N_file-32.parquet",
        "algo=gcm,mode=PF,aad=supply,partial=Y,keymeta=Y_file-16.parquet",
        "algo=gcm,mode=PF,aad=supply,partial=Y,keymeta=Y_file-32.parquet",
        "algo=gcm,mode=PF,aad=supply,uniform=Y_file-16.parquet",
        "algo=gcm,mode=PF,aad=supply,uniform=Y_file-32.parquet"
    };

    List<Object[]> out = new ArrayList<>();
    for (String s : samples) {
      Map<String, String> parts = parseName(s);
      String algo = parts.get("algo");
      String mode = parts.get("mode");
      String aad = parts.get("aad");
      boolean uniform = "Y".equals(parts.get("uniform"));
      String layout = uniform ? "uniform" : "partial";
      String keymeta = parts.getOrDefault("keymeta", "NA");
      int size = Integer.parseInt(parts.get("size"));
      out.add(new Object[] { algo, mode, aad, layout, keymeta, size, s });
    }
    return out;
  }

  private static Map<String, String> parseName(String filename) {
    // e.g. "algo=gcm_ctr,mode=EF,aad=stored,partial=Y,keymeta=Y_file-16.parquet"
    Map<String, String> m = new HashMap<>();
    String[] halves = filename.split("_file-");
    String left = halves[0];
    String right = halves[1];
    m.put("size", right.replace(".parquet", ""));
    for (String kv : left.split(",")) {
      String[] p = kv.split("=");
      m.put(p[0], p[1]);
    }
    return m;
  }

  // ---------------- test ----------------

  @DisplayName("Validate encryption metadata for all generated samples (spawned JVM)")
  @ParameterizedTest(name = "{index}: {0},{1},{2},{3},keymeta={4},k{5}")
  @MethodSource("cases")
  void matrix(String algo, String mode, String aad, String layout, String keymeta, int keySize, String fileName)
      throws Exception {
    File f = new File(OUT_PATH.toString(), fileName);
    assertTrue(f.exists(), "Missing sample: " + f.getPath() + " (run ParquetGenerateAll first)");

    List<String> cmd = new ArrayList<>();
    cmd.add(System.getProperty("java.home") + File.separator + "bin" +
        File.separator + "java");
    // use the current test runtime classpath so ParquetInspect can load
    // dependencies
    cmd.add("-cp");
    cmd.add(System.getProperty("java.class.path"));
    cmd.add("org.example.encrypted_parquet_inspector.Inspector");
    cmd.add(f.getPath());
    cmd.add(USER_KEY);
    if ("supply".equals(aad)) {
      cmd.add(AAD_PREFIX);
    }

    ProcessBuilder pb = new ProcessBuilder(cmd);
    pb.redirectErrorStream(true);
    Process p = pb.start();

    StringBuilder sb = new StringBuilder();
    try (BufferedReader br = new BufferedReader(
        new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
      String line;
      while ((line = br.readLine()) != null)
        sb.append(line).append('\n');
    }
    int code = p.waitFor();
    assertEquals(0, code, "Inspector exit code " + code + " for " + f.getName() + "\nOutput:\n" + sb);

    JsonNode root = OM.readTree(sb.toString());
    if (root.has("error")) {
      fail("Inspector error: " + root.get("error").asText() + " - " +
          root.get("message").asText());
    }

    // ---- Assertions ----
    JsonNode enc = root.get("encryption");
    assertNotNull(enc, "no 'encryption' node");

    // algorithm
    String expectedAlg = "gcm".equals(algo) ? "AES_GCM_V1" : "AES_GCM_CTR_V1";
    assertEquals(expectedAlg, enc.get("algorithm").asText(), "algorithm mismatch");

    // EF/PF
    String expectedFooterMode = "EF".equals(mode) ? "ENCRYPTED_FOOTER" : "PLAINTEXT_FOOTER";
    assertEquals(expectedFooterMode, enc.get("footerMode").asText(), "footerMode mismatch");
    assertEquals(expectedFooterMode, enc.get("type").asText(), "type mismatch");

    // AAD inference
    String expectedAad = Map.of("none", "none", "stored", "stored", "supply", "supply").get(aad);
    assertEquals(expectedAad, enc.get("inferredAadMode").asText(), "inferredAadMode mismatch");

    // Layout inference
    String expectedLayout = "uniform".equals(layout) ? "uniform" : "partial";
    assertEquals(expectedLayout, enc.get("inferredLayout").asText(), "inferredLayout mismatch");

    if ("PF".equals(mode)) {
      if ("partial".equals(layout)) {
        JsonNode pfKeys = enc.get("columnKeyMetadataPF");
        assertNotNull(pfKeys, "PF partial should expose columnKeyMetadataPF");
        Map<String, JsonNode> byPath = new HashMap<>();
        for (JsonNode n : pfKeys)
          byPath.put(n.get("path").asText(), n);
        assertTrue(byPath.containsKey("salary"), "missing salary record");
        assertTrue(byPath.containsKey("ssn"), "missing ssn record");

        if ("Y".equals(keymeta)) {
          assertEquals("k-col-salary", textOrNull(byPath.get("salary"),
              "columnKeyId"));
          assertEquals("k-col-ssn", textOrNull(byPath.get("ssn"), "columnKeyId"));
        } else {
          assertNull(textOrNull(byPath.get("salary"), "columnKeyId"));
          assertNull(textOrNull(byPath.get("ssn"), "columnKeyId"));
        }
      } else {
        // PF uniform: no columnKeyMetadataPF
        assertTrue(enc.get("columnKeyMetadataPF") == null ||
            enc.get("columnKeyMetadataPF").isNull(),
            "PF uniform should not include columnKeyMetadataPF");
      }
    } else { // EF
      if ("partial".equals(layout)) {
        JsonNode fk = enc.get("efFooterKeyColumns");
        assertNotNull(fk, "EF partial should include efFooterKeyColumns");
        List<String> list = toList(fk);
        assertTrue(list.containsAll(PARTIAL_FOOTER_KEY_COLS),
            "EF partial footer-key cols must include " + PARTIAL_FOOTER_KEY_COLS);

        if ("Y".equals(keymeta)) {
          JsonNode encountered = enc.get("encounteredColumnKeyIds");
          assertNotNull(encountered, "EF partial should expose encounteredColumnKeyIds when keymeta=Y");
          List<String> ids = toList(encountered);
          assertTrue(ids.containsAll(List.of("k-col-salary", "k-col-ssn")),
              "EF partial should encounter both column key IDs");
        }
      } else {
        // EF uniform: all columns decrypted by footer key
        JsonNode fk = enc.get("efFooterKeyColumns");
        assertNotNull(fk, "EF uniform should include efFooterKeyColumns");
        List<String> list = toList(fk);
        assertTrue(list.containsAll(COLS) && list.size() == COLS.size(),
            "EF uniform should list all columns as footer-key columns");
      }
    }
  }

  // ---------------- helpers ----------------

  private static List<String> toList(JsonNode arr) {
    ArrayList<String> out = new ArrayList<>();
    if (arr != null && arr.isArray())
      for (JsonNode n : arr)
        out.add(n.asText());
    return out;
  }

  private static String textOrNull(JsonNode n, String field) {
    if (n == null)
      return null;
    JsonNode v = n.get(field);
    return v == null || v.isNull() ? null : v.asText();
  }
}
