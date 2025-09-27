package org.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.*;
import org.apache.hadoop.fs.FileSystem;
import org.apache.parquet.ParquetReadOptions;
import org.apache.parquet.crypto.DecryptionKeyRetriever;
import org.apache.parquet.crypto.FileDecryptionProperties;
import org.apache.parquet.format.EncryptionAlgorithm;
import org.apache.parquet.format.FileCryptoMetaData;
import org.apache.parquet.hadoop.ParquetFileReader;
import org.apache.parquet.hadoop.util.HadoopInputFile;
import org.apache.parquet.hadoop.metadata.*;
import org.apache.parquet.io.InputFile;
import org.apache.parquet.io.SeekableInputStream;
import org.apache.parquet.schema.MessageType;
import org.apache.parquet.schema.Type;

import shaded.parquet.org.apache.thrift.protocol.TCompactProtocol;
import shaded.parquet.org.apache.thrift.transport.TIOStreamTransport;
import shaded.parquet.org.apache.thrift.transport.TTransportException;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class ParquetInspect {

  public static void main(String[] args) {
    System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "error");
    System.setProperty("org.slf4j.simpleLogger.log.org.apache", "error");
    System.setProperty("org.slf4j.simpleLogger.logFile", "System.err");
    System.setProperty("org.slf4j.simpleLogger.showDateTime", "false");
    System.setProperty("org.slf4j.simpleLogger.showThreadName", "false");
    System.setProperty("org.slf4j.simpleLogger.showLogName", "false");
    System.setProperty("org.slf4j.simpleLogger.showShortLogName", "false");

    int exit = 0;
    ObjectMapper om = new ObjectMapper();
    ObjectNode out = om.createObjectNode();

    try {
      if (args.length < 2) {
        throw new IllegalArgumentException("Usage: parquet-inspect <path> <key> [aadPrefix]");
      }

      final String fileArg = args[0];
      final byte[] footerKey = args[1].getBytes(StandardCharsets.UTF_8);
      final byte[] aadPrefix = (args.length >= 3 && !args[2].isEmpty())
          ? args[2].getBytes(StandardCharsets.UTF_8)
          : null;

      // Detect local vs. non-local (hdfs, s3a, etc.)
      final boolean isLocal = isLocalPath(fileArg);

      // Crypto meta from tail (local via RandomAccessFile; remote via Hadoop FS)
      final FileCryptoMetaData crypto = isLocal
          ? readCryptoMetaLocal(new File(fileArg))
          : readCryptoMetaHadoop(new Path(fileArg), hadoopLocalConf());

      final EncryptionAlgorithm alg = crypto.getEncryption_algorithm();
      final String algorithm = (alg != null && alg.isSetAES_GCM_V1()) ? "AES_GCM_V1"
          : (alg != null && alg.isSetAES_GCM_CTR_V1()) ? "AES_GCM_CTR_V1" : "UNKNOWN";
      final boolean supplyAadPrefix = (alg != null && alg.isSetAES_GCM_V1()) ? alg.getAES_GCM_V1().isSupply_aad_prefix()
          : (alg != null && alg.isSetAES_GCM_CTR_V1()) ? alg.getAES_GCM_CTR_V1().isSupply_aad_prefix() : false;

      // Decryption props
      final DecryptionKeyRetriever retriever = keyMetadata -> footerKey;
      FileDecryptionProperties.Builder decB = FileDecryptionProperties.builder()
          .withFooterKey(footerKey)
          .withKeyRetriever(retriever);
      if (aadPrefix != null && aadPrefix.length > 0)
        decB = decB.withAADPrefix(aadPrefix);
      final FileDecryptionProperties decProps = decB.build();

      final InputFile input = isLocal
          ? new LocalInputFile(new File(fileArg))
          : HadoopInputFile.fromPath(new Path(fileArg), hadoopLocalConf());

      ObjectNode encNode = om.createObjectNode();
      ArrayNode rgArray = om.createArrayNode();
      long totalRows = 0;

      try (ParquetFileReader pread = ParquetFileReader.open(
          input, ParquetReadOptions.builder().withDecryption(decProps).build())) {

        encNode.put("type", String.valueOf(pread.getFileMetaData().getEncryptionType()));
        encNode.put("algorithm", algorithm);
        encNode.put("supplyAadPrefix", supplyAadPrefix);
        encNode.put("aadSuppliedAtRead", aadPrefix != null);

        // Schema
        MessageType mt = pread.getFooter().getFileMetaData().getSchema();
        ObjectNode schemaNode = om.createObjectNode();
        schemaNode.put("string", mt.toString());
        ArrayNode fields = om.createArrayNode();
        for (Type t : mt.getFields()) {
          ObjectNode f = om.createObjectNode();
          f.put("name", t.getName());
          f.put("repetition", String.valueOf(t.getRepetition()));
          f.put("originalType", t.getOriginalType() == null ? null : t.getOriginalType().name());
          f.put("primitive", t.isPrimitive());
          if (t.isPrimitive()) {
            f.put("primitiveTypeName", t.asPrimitiveType().getPrimitiveTypeName().name());
          }
          fields.add(f);
        }
        schemaNode.set("fields", fields);
        out.set("schema", schemaNode);

        // Row groups & columns
        List<BlockMetaData> blocks = pread.getFooter().getBlocks();
        for (int i = 0; i < blocks.size(); i++) {
          BlockMetaData rg = blocks.get(i);
          ObjectNode rgNode = om.createObjectNode();
          rgNode.put("index", i);
          rgNode.put("rowCount", rg.getRowCount());
          rgNode.put("totalByteSize", rg.getTotalByteSize());
          totalRows += rg.getRowCount();

          ArrayNode cols = om.createArrayNode();
          for (ColumnChunkMetaData c : rg.getColumns()) {
            ObjectNode col = om.createObjectNode();
            col.put("path", c.getPath().toDotString());
            col.put("type", c.getPrimitiveType().getPrimitiveTypeName().name());
            col.put("codec", String.valueOf(c.getCodec()));
            col.put("totalSize", c.getTotalSize());
            col.put("dataPageOffset", c.getFirstDataPageOffset());
            col.put("dictionaryPageOffset", c.getDictionaryPageOffset());
            col.put("hasDictionaryPage", c.getDictionaryPageOffset() > 0);
            col.put("isEncrypted", c.isEncrypted());
            cols.add(col);
          }
          rgNode.set("columns", cols);
          rgArray.add(rgNode);
        }
      }

      out.put("file", fileArg);
      out.set("encryption", encNode);
      out.set("rowGroups", rgArray);

      ObjectNode totals = om.createObjectNode();
      totals.put("rowGroups", rgArray.size());
      totals.put("rowCount", totalRows);
      out.set("totals", totals);

      System.out.println(om.writerWithDefaultPrettyPrinter().writeValueAsString(out));

    } catch (Throwable t) {
      exit = 1;
      try {
        ObjectMapper om2 = new ObjectMapper();
        ObjectNode err = om2.createObjectNode();
        err.put("error", t.getClass().getName());
        err.put("message", String.valueOf(t.getMessage()));
        ArrayNode st = om2.createArrayNode();
        for (StackTraceElement el : t.getStackTrace())
          st.add(el.toString());
        err.set("stack", st);
        System.out.println(om2.writerWithDefaultPrettyPrinter().writeValueAsString(err));
      } catch (Exception ignore) {
        System.err.println("Fatal: " + t);
      }
    }
    System.exit(exit);
  }

  private static boolean isLocalPath(String p) {
    // Treat as local if it has no URI scheme or starts with / or ./ or ../
    return !(p.startsWith("hdfs://") || p.startsWith("s3a://") || p.startsWith("s3://") || p.startsWith("gs://"));
  }

  private static Configuration hadoopLocalConf() {
    Configuration conf = new Configuration(false);
    conf.set("fs.defaultFS", "file:///");
    return conf;
  }

  // ---- Tail reader: local file (RandomAccessFile), no Hadoop involved ----
  static FileCryptoMetaData readCryptoMetaLocal(File f) throws IOException {
    try (RandomAccessFile raf = new RandomAccessFile(f, "r")) {
      long len = raf.length();
      if (len < 8)
        throw new IOException("File too small to be Parquet");

      raf.seek(len - 8);
      int combinedLenLE = raf.readInt();
      int combinedLen = Integer.reverseBytes(combinedLenLE);
      int magic = raf.readInt();
      if (magic != 0x50415245)
        throw new IOException("Not an encrypted Parquet tail (magic mismatch).");

      long tailStart = len - 8L - combinedLen;
      if (tailStart < 0)
        throw new IOException("Bad tail length");

      raf.seek(tailStart);

      // Wrap the remaining bytes in a stream for Thrift
      InputStream is = new InputStream() {
        long pos = tailStart;

        @Override
        public int read() throws IOException {
          if (pos >= len)
            return -1;
          raf.seek(pos++);
          return raf.read();
        }

        @Override
        public int read(byte[] b, int off, int l) throws IOException {
          raf.seek(pos);
          int r = raf.read(b, off, l);
          if (r > 0)
            pos += r;
          return r;
        }
      };

      final TIOStreamTransport transport;
      try {
        transport = new TIOStreamTransport(is);
      } catch (TTransportException e) {
        throw new IOException("Failed to create Thrift transport", e);
      }
      TCompactProtocol proto = new TCompactProtocol(transport);

      FileCryptoMetaData crypto = new FileCryptoMetaData();
      try {
        crypto.read(proto);
      } catch (Exception e) {
        throw new IOException("Failed to read FileCryptoMetaData", e);
      }
      return crypto;
    }
  }

  // ---- Tail reader: Hadoop FS (only for non-local URIs) ----
  static FileCryptoMetaData readCryptoMetaHadoop(Path p, Configuration conf) throws IOException {
    FileSystem fs = p.getFileSystem(conf);
    try (FSDataInputStream in = fs.open(p)) {
      long len = fs.getFileStatus(p).getLen();

      in.seek(len - 8);
      int combinedLenLE = in.readInt();
      int combinedLen = Integer.reverseBytes(combinedLenLE);
      int magic = in.readInt();
      if (magic != 0x50415245)
        throw new IOException("Not an encrypted Parquet tail (magic mismatch).");

      long tailStart = len - 8L - combinedLen;
      in.seek(tailStart);

      final TIOStreamTransport transport;
      try {
        transport = new TIOStreamTransport(in);
      } catch (TTransportException e) {
        throw new IOException("Failed to create Thrift transport", e);
      }
      TCompactProtocol proto = new TCompactProtocol(transport);

      FileCryptoMetaData crypto = new FileCryptoMetaData();
      try {
        crypto.read(proto);
      } catch (Exception e) {
        throw new IOException("Failed to read FileCryptoMetaData", e);
      }
      return crypto;
    }
  }

  static final class LocalInputFile implements InputFile {
    private final File file;

    LocalInputFile(File file) {
      this.file = file;
    }

    @Override
    public long getLength() throws IOException {
      return file.length();
    }

    @Override
    public SeekableInputStream newStream() throws IOException {
      final RandomAccessFile raf = new RandomAccessFile(file, "r");
      final FileChannel ch = raf.getChannel();

      return new SeekableInputStream() {
        @Override
        public int read() throws IOException {
          return raf.read();
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
          return raf.read(b, off, len);
        }

        @Override
        public int read(ByteBuffer byteBuffer) throws IOException {
          return ch.read(byteBuffer);
        }

        @Override
        public void readFully(byte[] bytes) throws IOException {
          readFully(bytes, 0, bytes.length);
        }

        @Override
        public void readFully(byte[] bytes, int off, int len) throws IOException {
          int total = 0;
          while (total < len) {
            int r = raf.read(bytes, off + total, len - total);
            if (r < 0)
              throw new EOFException("Reached EOF reading " + len + " bytes");
            total += r;
          }
        }

        @Override
        public void readFully(ByteBuffer byteBuffer) throws IOException {
          int remaining = byteBuffer.remaining();
          byte[] temp = new byte[remaining];
          readFully(temp, 0, remaining);
          byteBuffer.put(temp);
        }

        @Override
        public long getPos() throws IOException {
          return raf.getFilePointer();
        }

        @Override
        public void seek(long newPos) throws IOException {
          raf.seek(newPos);
        }

        @Override
        public void close() throws IOException {
          raf.close();
        }
      };
    }
  }
}
