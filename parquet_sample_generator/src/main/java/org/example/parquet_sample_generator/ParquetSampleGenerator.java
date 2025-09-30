package org.example.parquet_sample_generator;

import org.apache.hadoop.conf.Configuration;
import org.apache.parquet.column.ParquetProperties;
import org.apache.parquet.example.data.Group;
import org.apache.parquet.example.data.simple.SimpleGroup;
import org.apache.parquet.hadoop.ParquetWriter;
import org.apache.parquet.hadoop.example.ExampleParquetWriter;
import org.apache.parquet.hadoop.metadata.ColumnPath;
import org.apache.parquet.hadoop.metadata.CompressionCodecName;
import org.apache.parquet.io.OutputFile;
import org.apache.parquet.io.PositionOutputStream;
import org.apache.parquet.schema.LogicalTypeAnnotation;
import org.apache.parquet.schema.MessageType;
import org.apache.parquet.schema.Types;
import org.apache.parquet.schema.PrimitiveType.PrimitiveTypeName;
import org.apache.parquet.crypto.*;

import static org.apache.parquet.schema.PrimitiveType.PrimitiveTypeName.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Collectors;

public class ParquetSampleGenerator {

  // ======= Schema used for all files =======
  private static final MessageType SCHEMA = Types.buildMessage()
      .required(BINARY).as(LogicalTypeAnnotation.stringType()).named("name")
      .required(PrimitiveTypeName.INT32).named("age")
      .optional(PrimitiveTypeName.DOUBLE).named("salary")
      .optional(BINARY).as(LogicalTypeAnnotation.stringType()).named("ssn")
      .named("demo");

  private static final String COL_NAME = "name";
  private static final String COL_AGE = "age";
  private static final String COL_SALARY = "salary";
  private static final String COL_SSN = "ssn";

  private enum Algo {
    GCM, GCM_CTR
  }

  private enum FooterMode {
    EF, PF
  }

  private enum AADMode {
    NONE, STORED, SUPPLY
  }

  static void whereIsCrypto() {
    String[] names = {
        "org.apache.parquet.crypto.FileEncryptionProperties",
        "org.apache.parquet.crypto.DecryptionProperties",
        "org.apache.parquet.crypto.ParquetCipher"
    };
    for (String n : names) {
      try {
        Class<?> c = Class.forName(n);
        var src = c.getProtectionDomain().getCodeSource();
        System.out.println(n + " -> " + (src == null ? "(bootstrap)" : src.getLocation()));
      } catch (ClassNotFoundException e) {
        System.out.println(n + " -> NOT FOUND");
      }
    }
  }

  public static void main(String[] args) throws Exception {
    whereIsCrypto();
    quietSlf4j();

    if (args.length < 2) {
      System.err.println("Usage: parquet-generate-all <outDir> <baseKeyUtf8> [--rows=N] [--aadPrefix=STR]");
      System.exit(2);
    }

    final String outDir = args[0];
    final byte[] baseKey = args[1].getBytes(StandardCharsets.UTF_8);
    int rows = 10;
    byte[] aadPrefix = null;

    for (int i = 2; i < args.length; i++) {
      String a = args[i];
      if (a.startsWith("--rows=")) {
        rows = Integer.parseInt(a.substring("--rows=".length()));
      } else if (a.startsWith("--aadPrefix=")) {
        String s = a.substring("--aadPrefix=".length());
        if (!s.isEmpty())
          aadPrefix = s.getBytes(StandardCharsets.UTF_8);
      } else {
        throw new IllegalArgumentException("Unknown arg: " + a);
      }
    }

    List<Algo> algos = Arrays.asList(Algo.GCM, Algo.GCM_CTR);
    List<FooterMode> footerModes = Arrays.asList(FooterMode.EF, FooterMode.PF);
    List<AADMode> aadModes = Arrays.asList(AADMode.NONE, AADMode.STORED, AADMode.SUPPLY);
    boolean[] uniformFlags = new boolean[] { true, false };
    boolean[] keyMetaFlags = new boolean[] { true, false };
    int[] keySizes = new int[] { 16, 32 };

    int emitted = 0;
    for (Algo algo : algos) {
      for (FooterMode mode : footerModes) {
        for (AADMode aadMode : aadModes) {
          byte[] thisAad = (aadMode == AADMode.NONE)
              ? null
              : (aadPrefix != null ? aadPrefix : "dataset_partition_2025-09-28".getBytes(StandardCharsets.UTF_8));

          for (int keySize : keySizes) {
            byte[] footerKey = deriveKey(baseKey, "footer", keySize);

            // Uniform: ALL columns encrypted with footer key
            if (contains(uniformFlags, true)) {
              FileEncryptionProperties enc = buildEncPropsUniform(footerKey, "kf", algo, mode, aadMode, thisAad);
              String rel = pathFor(outDir, algo, mode, aadMode, true, false, true, keySize);
              writeOne(rel, enc, rows);
              emitted++;
            }

            // Partial: only salary + ssn encrypted with column keys
            if (contains(uniformFlags, false)) {
              for (boolean withKeyMeta : keyMetaFlags) {
                byte[] keySalary = deriveKey(baseKey, "col_salary", keySize);
                byte[] keySSN = deriveKey(baseKey, "col_ssn", keySize);

                FileEncryptionProperties enc = buildEncPropsPartial(
                    footerKey, "kf",
                    algo, mode, aadMode, thisAad,
                    keySalary, withKeyMeta ? "k-col-salary" : null,
                    keySSN, withKeyMeta ? "k-col-ssn" : null,
                    withKeyMeta);

                String rel = pathFor(outDir, algo, mode, aadMode, false, withKeyMeta, false, keySize);
                writeOne(rel, enc, rows);
                emitted++;
              }
            }
          }
        }
      }
    }

    System.out.println("{\"ok\":true,\"dir\":\"" + outDir + "\",\"files\":" + emitted + "}");
  }

  private static boolean contains(boolean[] arr, boolean val) {
    for (boolean b : arr)
      if (b == val)
        return true;
    return false;
  }

  // ---------- Encryption builders ----------

  private static FileEncryptionProperties buildEncPropsUniform(
      byte[] footerKey, String footerKeyId,
      Algo algo, FooterMode mode, AADMode aadMode, byte[] aadPrefix) {

    ParquetCipher cipher = (algo == Algo.GCM) ? ParquetCipher.AES_GCM_V1 : ParquetCipher.AES_GCM_CTR_V1;

    FileEncryptionProperties.Builder b = FileEncryptionProperties.builder(footerKey)
        .withFooterKeyID(footerKeyId)
        .withAlgorithm(cipher);

    if (mode == FooterMode.PF) {
      // PF + encryption present => parquet-mr appends nonce|tag (signature) after
      // footer
      b = b.withPlaintextFooter();
    }

    if (aadMode != AADMode.NONE && aadPrefix != null) {
      b = b.withAADPrefix(aadPrefix);
      if (aadMode == AADMode.SUPPLY) {
        try {
          b = b.withoutAADPrefixStorage();
        } catch (Throwable ignore) {
          /* older parquet-mr */ }
      }
    }

    // Uniform encryption (no per-column keys list)
    return b.build();
  }

  private static FileEncryptionProperties buildEncPropsPartial(
      byte[] footerKey, String footerKeyId,
      Algo algo, FooterMode mode, AADMode aadMode, byte[] aadPrefix,
      byte[] salaryKey, String salaryKeyId,
      byte[] ssnKey, String ssnKeyId,
      boolean includeKeyId) {

    ParquetCipher cipher = (algo == Algo.GCM) ? ParquetCipher.AES_GCM_V1 : ParquetCipher.AES_GCM_CTR_V1;

    ColumnEncryptionProperties.Builder salary = ColumnEncryptionProperties
        .builder(ColumnPath.get(COL_SALARY))
        .withKey(salaryKey);
    if (includeKeyId && salaryKeyId != null)
      salary = salary.withKeyID(salaryKeyId);

    ColumnEncryptionProperties.Builder ssn = ColumnEncryptionProperties
        .builder(ColumnPath.get(COL_SSN))
        .withKey(ssnKey);
    if (includeKeyId && ssnKeyId != null)
      ssn = ssn.withKeyID(ssnKeyId);

    Map<ColumnPath, ColumnEncryptionProperties> encCols = new LinkedHashMap<>();
    encCols.put(ColumnPath.get(COL_SALARY), salary.build());
    encCols.put(ColumnPath.get(COL_SSN), ssn.build());

    FileEncryptionProperties.Builder b = FileEncryptionProperties.builder(footerKey)
        .withFooterKeyID(footerKeyId)
        .withAlgorithm(cipher)
        .withEncryptedColumns(encCols);

    if (mode == FooterMode.PF) {
      // PF + some encrypted columns => parquet-mr signs the plaintext footer
      b = b.withPlaintextFooter();
    }
    if (aadMode != AADMode.NONE && aadPrefix != null) {
      b = b.withAADPrefix(aadPrefix);
      if (aadMode == AADMode.SUPPLY) {
        try {
          b = b.withoutAADPrefixStorage();
        } catch (Throwable ignore) {
          /* older parquet-mr */ }
      }
    }
    return b.build();
  }

  // ---------- Writer ----------

  private static void writeOne(String outPath, FileEncryptionProperties encProps, int rows) throws IOException {
    File f = new File(outPath);
    if (f.getParentFile() != null)
      f.getParentFile().mkdirs();

    ParquetWriter<Group> writer;
    if (isLocalPath(outPath)) {
      writer = ExampleParquetWriter.builder(new LocalOutputFile(f))
          .withType(SCHEMA)
          .withDictionaryEncoding(true)
          .withValidation(false)
          .withWriterVersion(ParquetProperties.WriterVersion.PARQUET_1_0)
          .withCompressionCodec(CompressionCodecName.SNAPPY)
          .withEncryption(encProps)
          .build();
    } else {
      Configuration conf = new Configuration(false);
      conf.set("fs.defaultFS", "file:///");
      org.apache.hadoop.fs.Path path = new org.apache.hadoop.fs.Path(outPath);

      writer = ExampleParquetWriter.builder(
          org.apache.parquet.hadoop.util.HadoopOutputFile.fromPath(path, conf))
          .withType(SCHEMA)
          .withConf(conf)
          .withDictionaryEncoding(true)
          .withValidation(false)
          .withWriterVersion(ParquetProperties.WriterVersion.PARQUET_1_0)
          .withCompressionCodec(CompressionCodecName.SNAPPY)
          .withEncryption(encProps)
          .build();
    }

    try (writer) {
      for (int i = 0; i < rows; i++) {
        Group g = new SimpleGroup(SCHEMA);
        g.add(COL_NAME, "User-" + i);
        g.add(COL_AGE, 20 + (i % 30));
        if (i % 2 == 0)
          g.add(COL_SALARY, 50000.0 + i * 123.45);
        if (i % 3 == 0)
          g.add(COL_SSN, String.format(Locale.ROOT, "123-45-%04d", i));
        writer.write(g);
      }
    }
  }

  // ---------- Paths & utilities ----------

  private static String pathFor(String baseDir, Algo algo, FooterMode fm, AADMode aad,
      boolean uniform, boolean keyMeta, boolean uniformFlag, int keySize) {
    List<String> parts = new ArrayList<>();
    parts.add("algo=" + (algo == Algo.GCM ? "gcm" : "gcm_ctr"));
    parts.add("mode=" + fm.name());
    parts.add("aad=" + (aad == AADMode.NONE ? "none" : (aad == AADMode.STORED ? "stored" : "supply")));
    if (uniform) {
      parts.add("uniform=Y");
    } else {
      parts.add("partial=Y");
      parts.add("keymeta=" + (keyMeta ? "Y" : "N"));
    }
    String dir = parts.stream().collect(Collectors.joining(","));
    return baseDir + File.separator + dir + "_" + ("file-" + keySize + ".parquet");
  }

  private static byte[] deriveKey(byte[] base, String label, int sizeBytes) {
    try {
      MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
      sha256.update(base);
      sha256.update((byte) 0);
      sha256.update(label.getBytes(StandardCharsets.UTF_8));
      byte[] full = sha256.digest();
      if (sizeBytes == 16)
        return Arrays.copyOf(full, 16);
      if (sizeBytes == 24)
        return Arrays.copyOf(full, 24);
      if (sizeBytes == 32)
        return Arrays.copyOf(full, 32);
      throw new IllegalArgumentException("Unsupported key size: " + sizeBytes);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static boolean isLocalPath(String p) {
    return !(p.startsWith("hdfs://") || p.startsWith("s3a://") || p.startsWith("s3://") || p.startsWith("gs://"));
  }

  private static void quietSlf4j() {
    System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "error");
    System.setProperty("org.slf4j.simpleLogger.log.org.apache", "error");
    System.setProperty("org.slf4j.simpleLogger.logFile", "System.err");
    System.setProperty("org.slf4j.simpleLogger.showDateTime", "false");
    System.setProperty("org.slf4j.simpleLogger.showThreadName", "false");
    System.setProperty("org.slf4j.simpleLogger.showLogName", "false");
    System.setProperty("org.slf4j.simpleLogger.showShortLogName", "false");
  }

  // --- LocalOutputFile helper ---
  static final class LocalOutputFile implements OutputFile {
    private final File file;

    LocalOutputFile(File file) {
      this.file = file;
    }

    @Override
    public PositionOutputStream create(long blockSizeHint) throws IOException {
      File parent = file.getParentFile();
      if (parent != null)
        parent.mkdirs();
      final FileOutputStream fos = new FileOutputStream(file);
      final FileChannel ch = fos.getChannel();
      return new PositionOutputStream() {
        @Override
        public long getPos() throws IOException {
          return ch.position();
        }

        @Override
        public void write(int b) throws IOException {
          fos.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
          fos.write(b, off, len);
        }

        @Override
        public void close() throws IOException {
          fos.flush();
          fos.close();
        }
      };
    }

    @Override
    public PositionOutputStream createOrOverwrite(long blockSizeHint) throws IOException {
      return create(blockSizeHint);
    }

    @Override
    public boolean supportsBlockSize() {
      return false;
    }

    @Override
    public long defaultBlockSize() {
      return 0L;
    }
  }
}
