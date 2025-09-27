package org.example;

import org.apache.hadoop.conf.Configuration;
import org.apache.parquet.column.ParquetProperties;
import org.apache.parquet.example.data.Group;
import org.apache.parquet.example.data.simple.SimpleGroup;
import org.apache.parquet.hadoop.ParquetWriter;
import org.apache.parquet.hadoop.example.ExampleParquetWriter;
import org.apache.parquet.schema.MessageType;
import org.apache.parquet.schema.Types;
import org.apache.parquet.schema.LogicalTypeAnnotation;
import org.apache.parquet.schema.PrimitiveType.PrimitiveTypeName;
import static org.apache.parquet.schema.PrimitiveType.PrimitiveTypeName.*;
import org.apache.parquet.io.OutputFile;
import org.apache.parquet.io.PositionOutputStream;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;

import org.apache.parquet.crypto.FileEncryptionProperties;
import org.apache.parquet.crypto.ParquetCipher;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class ParquetGenerate {

  private static void quietSlf4j() {
    System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "error");
    System.setProperty("org.slf4j.simpleLogger.log.org.apache", "error");
    System.setProperty("org.slf4j.simpleLogger.logFile", "System.err");
    System.setProperty("org.slf4j.simpleLogger.showDateTime", "false");
    System.setProperty("org.slf4j.simpleLogger.showThreadName", "false");
    System.setProperty("org.slf4j.simpleLogger.showLogName", "false");
    System.setProperty("org.slf4j.simpleLogger.showShortLogName", "false");
  }

  public static void main(String[] args) throws Exception {
    quietSlf4j();

    if (args.length < 2) {
      System.err.println(
          "Usage: parquet-generate <outPath> <footerKeyUtf8> [--rows=N] [--aadPrefix=STR] [--algo=gcm|gcm_ctr]");
      System.exit(2);
    }

    final String outPath = args[0];
    final byte[] footerKey = args[1].getBytes(StandardCharsets.UTF_8);
    int rows = 10;
    byte[] aadPrefix = null;
    ParquetCipher algo = ParquetCipher.AES_GCM_V1;

    for (int i = 2; i < args.length; i++) {
      String a = args[i];
      if (a.startsWith("--rows=")) {
        rows = Integer.parseInt(a.substring("--rows=".length()));
      } else if (a.startsWith("--aadPrefix=")) {
        String s = a.substring("--aadPrefix=".length());
        if (!s.isEmpty())
          aadPrefix = s.getBytes(StandardCharsets.UTF_8);
      } else if (a.startsWith("--algo=")) {
        String v = a.substring("--algo=".length()).toLowerCase(Locale.ROOT);
        if (v.equals("gcm"))
          algo = ParquetCipher.AES_GCM_V1;
        else if (v.equals("gcm_ctr") || v.equals("gcm-ctr"))
          algo = ParquetCipher.AES_GCM_CTR_V1;
        else
          throw new IllegalArgumentException("Unknown --algo: " + v);
      } else {
        throw new IllegalArgumentException("Unknown arg: " + a);
      }
    }

    // Parquet recommends 16/24/32-byte keys for AES; enforce minimally:
    if (!(footerKey.length == 16 || footerKey.length == 24 || footerKey.length == 32)) {
      throw new IllegalArgumentException("footerKey must be 16/24/32 bytes (AES key)");
    }

    // Simple demo schema (string,int,double,string)
    MessageType schema = Types.buildMessage()
        .required(BINARY).as(LogicalTypeAnnotation.stringType()).named("name")
        .required(INT32).named("age")
        .optional(PrimitiveTypeName.DOUBLE).named("salary")
        .optional(BINARY).as(LogicalTypeAnnotation.stringType()).named("ssn")
        .named("demo");

    // Encryption: encrypt footer + all columns with same footer key (simple &
    // solid)
    FileEncryptionProperties.Builder encB = FileEncryptionProperties.builder(footerKey)
        .withFooterKeyID("kf") // key metadata/id (helps retrieval on read)
        .withAlgorithm(algo);

    if (aadPrefix != null && aadPrefix.length > 0) {
      encB = encB.withAADPrefix(aadPrefix);
    }

    FileEncryptionProperties encProps = encB.build();

    ParquetWriter<Group> writer;

    if (isLocalPath(outPath)) {
      // No Hadoop involved on local files (avoids UGI/JDK21 issue)
      writer = ExampleParquetWriter.builder(new LocalOutputFile(new File(outPath)))
          .withType(schema)
          .withDictionaryEncoding(true)
          .withValidation(false)
          .withWriterVersion(ParquetProperties.WriterVersion.PARQUET_1_0)
          .withCompressionCodec(org.apache.parquet.hadoop.metadata.CompressionCodecName.SNAPPY)
          .withEncryption(encProps)
          .build();
    } else {
      // Remote FS needs Hadoop; OK under Java 17. If you keep this path, also add:
      // conf.set("hadoop.security.authentication", "simple");
      // and optionally: UserGroupInformation.setConfiguration(conf);
      Configuration conf = new Configuration(false);
      conf.set("fs.defaultFS", "file:///");
      org.apache.hadoop.fs.Path path = new org.apache.hadoop.fs.Path(outPath);

      writer = ExampleParquetWriter.builder(
          org.apache.parquet.hadoop.util.HadoopOutputFile.fromPath(path, conf))
          .withType(schema)
          .withConf(conf)
          .withDictionaryEncoding(true)
          .withValidation(false)
          .withWriterVersion(ParquetProperties.WriterVersion.PARQUET_1_0)
          .withCompressionCodec(org.apache.parquet.hadoop.metadata.CompressionCodecName.SNAPPY)
          .withEncryption(encProps)
          .build();
    }

    try (writer) {
      for (int i = 0; i < rows; i++) {
        Group g = new SimpleGroup(schema);
        g.add("name", "User-" + i);
        g.add("age", 20 + (i % 30));
        if (i % 2 == 0)
          g.add("salary", 50000.0 + i * 123.45);
        if (i % 3 == 0)
          g.add("ssn", String.format(Locale.ROOT, "123-45-%04d", i));
        writer.write(g);
      }
    }

    System.out.println("{\"ok\":true,"
        + "\"file\":\"" + outPath + "\","
        + "\"rows\":" + rows + ","
        + "\"algo\":\"" + algo + "\","
        + "\"aadSupplied\":" + (aadPrefix != null) + "}");
  }

  private static boolean isLocalPath(String p) {
    return !(p.startsWith("hdfs://") || p.startsWith("s3a://") || p.startsWith("s3://") || p.startsWith("gs://"));
  }

  static final class LocalOutputFile implements OutputFile {
    private final File file;

    LocalOutputFile(File file) {
      this.file = file;
    }

    @Override
    public PositionOutputStream create(long blockSizeHint) throws IOException {
      File parent = file.getParentFile();
      if (parent != null) {
        parent.mkdirs();
      }
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
