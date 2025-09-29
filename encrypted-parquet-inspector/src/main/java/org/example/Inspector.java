package org.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.parquet.ParquetReadOptions;
import org.apache.parquet.crypto.DecryptionKeyRetriever;
import org.apache.parquet.crypto.FileDecryptionProperties;
import org.apache.parquet.crypto.ParquetCryptoRuntimeException;
import org.apache.parquet.format.EncryptionAlgorithm;
import org.apache.parquet.format.FileCryptoMetaData;
import org.apache.parquet.hadoop.ParquetFileReader;
import org.apache.parquet.hadoop.metadata.BlockMetaData;
import org.apache.parquet.hadoop.metadata.ColumnChunkMetaData;
import org.apache.parquet.io.InputFile;
import org.apache.parquet.io.SeekableInputStream;
import org.apache.parquet.schema.MessageType;
import org.apache.parquet.schema.Type;

import shaded.parquet.org.apache.thrift.protocol.TCompactProtocol;
import shaded.parquet.org.apache.thrift.transport.TIOStreamTransport;
import shaded.parquet.org.apache.thrift.transport.TTransportException;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public class Inspector {

  public static void main(String[] args) {
    quietSlf4j();

    int exit = 0;
    ObjectMapper om = new ObjectMapper();
    ObjectNode out = om.createObjectNode();

    try {
      if (args.length < 2) {
        throw new IllegalArgumentException(
            "Usage: inspector <file> <key> [--hex] [--aadPrefix=<utf8 or 0xHEX>]");
      }

      final String fileArg = args[0];
      final String keyArg = args[1];

      boolean keyIsHex = false;

      // Accept positional AAD prefix for compatibility with the test harness.
      // If args[2] is present and not a flag, treat it as the AAD prefix.
      byte[] aadPrefix = null;
      int argi = 2;
      if (args.length >= 3 && !args[2].startsWith("--")) {
        String v = args[2];
        if (v.startsWith("0x") || v.startsWith("0X")) {
          aadPrefix = hexToBytes(v.substring(2));
        } else {
          aadPrefix = v.getBytes(StandardCharsets.UTF_8);
        }
        argi = 3;
      }

      // Parse remaining flags (still support --hex and --aadPrefix=...)
      for (int i = argi; i < args.length; i++) {
        String a = args[i];
        if ("--hex".equals(a)) {
          keyIsHex = true;
        } else if (a.startsWith("--aadPrefix=")) {
          String v = a.substring("--aadPrefix=".length());
          if (v.startsWith("0x") || v.startsWith("0X")) {
            aadPrefix = hexToBytes(v.substring(2));
          } else {
            aadPrefix = v.getBytes(StandardCharsets.UTF_8);
          }
        } else {
          throw new IllegalArgumentException("Unknown arg: " + a);
        }
      }

      // Gentle warning: users sometimes paste hex but forget --hex
      if (!keyIsHex && looksLikeRawAesHex(keyArg)) {
        System.err.println("[warn] The key you passed looks like hex; did you mean to use --hex?");
      }

      final byte[] userKeyBytes = keyIsHex ? hexToBytes(keyArg) : keyArg.getBytes(StandardCharsets.UTF_8);

      // Try to read EF tail (no decryptor needed)
      FileCryptoMetaData cryptoTail = null;
      try {
        cryptoTail = readCryptoMetaLocal(new File(fileArg));
      } catch (IOException ignore) {
      }
      final boolean ef = (cryptoTail != null);

      // Collect encountered per-column key IDs (when decryptors are available)
      final Set<String> encounteredKeyIds = new LinkedHashSet<>();

      // Decryption candidates:
      // - For PF or non-encrypted files: try plaintext
      // - If key length is 16/24/32 => try as footer key
      // - Try “footer” derivation (SHA-256(user || 0x00 || "footer"), 128/256-bit)
      List<DecCand> candidates = new ArrayList<>();
      if (!ef)
        candidates.add(new DecCand(null, null));

      if (userKeyBytes.length == 16 || userKeyBytes.length == 24 || userKeyBytes.length == 32) {
        candidates.add(buildFooterProps(userKeyBytes, userKeyBytes, aadPrefix, encounteredKeyIds));
      }
      try {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(userKeyBytes);
        sha256.update((byte) 0);
        sha256.update("footer".getBytes(StandardCharsets.UTF_8));
        byte[] full = sha256.digest();
        candidates.add(buildFooterProps(userKeyBytes, Arrays.copyOf(full, 16), aadPrefix, encounteredKeyIds));
        candidates.add(buildFooterProps(userKeyBytes, Arrays.copyOf(full, 32), aadPrefix, encounteredKeyIds));
      } catch (Exception ignore) {
      }

      final InputFile input = new LocalInputFile(new File(fileArg));

      ObjectNode encNode = om.createObjectNode();
      ArrayNode rgArray = om.createArrayNode();
      long totalRows = 0;
      int totalColumnsSeen = 0;
      int encryptedColumns = 0;
      int plaintextColumns = 0;
      boolean anyColumnKeyMetadata = false;
      boolean anyEncryptedWithFooterKey = false;

      ParquetFileReader pread = null;
      boolean scanSucceeded = false;
      String algorithm = "UNKNOWN";
      boolean supplyAadPrefixFlag = false;
      boolean hasStoredAadPrefix = false;
      String storedAadPrefixHex = null;
      boolean hasFooterKeyMetadata = false;
      String footerKeyIdUtf8 = null;

      for (DecCand cand : candidates) {
        try {
          ParquetReadOptions opts = (cand.props == null)
              ? ParquetReadOptions.builder().build()
              : ParquetReadOptions.builder().withDecryption(cand.props).build();

          try {
            pread = ParquetFileReader.open(input, opts);
          } catch (ParquetCryptoRuntimeException e) {
            // Any crypto error here means this candidate didn't work. Try the next one.
            closeQuiet(pread);
            continue;
          }

          // Reset totals per attempt
          rgArray.removeAll();
          totalRows = 0;
          totalColumnsSeen = 0;
          encryptedColumns = 0;
          plaintextColumns = 0;
          anyColumnKeyMetadata = false;
          anyEncryptedWithFooterKey = false;

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

          boolean needDecrypt = false;

          final Set<String> efFkColsInline = new LinkedHashSet<>();

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
              col.put("isEncrypted", c.isEncrypted());

              totalColumnsSeen++;
              if (c.isEncrypted())
                encryptedColumns++;
              else
                plaintextColumns++;

              boolean decryptOkWithFooterKey = true;

              try {
                col.put("type", c.getPrimitiveType().getPrimitiveTypeName().name());
              } catch (ParquetCryptoRuntimeException e) {
                needDecrypt = needDecrypt || isNullDecryptor(e);
                decryptOkWithFooterKey = false;
                col.put("type", c.isEncrypted() ? "hidden" : null);
              } catch (Throwable t) {
                decryptOkWithFooterKey = false;
                col.put("type", c.isEncrypted() ? "hidden" : null);
              }

              try {
                col.put("codec", String.valueOf(c.getCodec()));
              } catch (ParquetCryptoRuntimeException e) {
                needDecrypt = needDecrypt || isNullDecryptor(e);
                decryptOkWithFooterKey = false;
                col.put("codec", c.isEncrypted() ? "hidden" : null);
              } catch (Throwable t) {
                decryptOkWithFooterKey = false;
                col.put("codec", c.isEncrypted() ? "hidden" : null);
              }

              try {
                col.put("totalSize", c.getTotalSize());
              } catch (Throwable ignore) {
              }
              try {
                col.put("dataPageOffset", c.getFirstDataPageOffset());
              } catch (Throwable ignore) {
              }
              try {
                col.put("dictionaryPageOffset", c.getDictionaryPageOffset());
                col.put("hasDictionaryPage", c.getDictionaryPageOffset() > 0);
              } catch (Throwable ignore) {
              }

              if (ef && cand.footerKeyBytes != null) {
                col.put("encryptedWithFooterKey", decryptOkWithFooterKey);
                if (decryptOkWithFooterKey) {
                  efFkColsInline.add(c.getPath().toDotString());
                }
              }
              cols.add(col);
            }
            rgNode.set("columns", cols);
            rgArray.add(rgNode);
          }

          // Determine PF/EF with sane defaults
          String encryptionTypeStr = String.valueOf(pread.getFileMetaData().getEncryptionType());
          String footerMode = ef
              ? "ENCRYPTED_FOOTER"
              : (encryptionTypeStr != null && encryptionTypeStr.toUpperCase(Locale.ROOT).contains("PLAINTEXT")
                  ? "PLAINTEXT_FOOTER"
                  : "PLAINTEXT_FOOTER"); // default to PF if not EF

          if ("PLAINTEXT_FOOTER".equals(footerMode)) {
            PFMeta pf = readPlaintextFooterMetaLocal(new File(fileArg));

            Map<Integer, Set<String>> pfFooterKeyCols = new LinkedHashMap<>();
            if (pf != null && pf.colKeys != null) {
              for (ColKeyMeta k : pf.colKeys) {
                if (k.encryptedWithFooterKey && k.columnPath != null) {
                  pfFooterKeyCols.computeIfAbsent(k.rowGroupIndex, i -> new LinkedHashSet<>())
                      .add(k.columnPath);
                }
              }
            }

            // Annotate existing rgArray with PF footer-key info
            if (!pfFooterKeyCols.isEmpty()) {
              for (int i = 0; i < rgArray.size(); i++) {
                ObjectNode rgNode = (ObjectNode) rgArray.get(i);
                ArrayNode cols = (ArrayNode) rgNode.get("columns");
                for (int j = 0; j < cols.size(); j++) {
                  ObjectNode col = (ObjectNode) cols.get(j);
                  String path = col.get("path").asText();
                  boolean fk = pfFooterKeyCols.getOrDefault(i, Collections.emptySet()).contains(path);
                  col.put("encryptedWithFooterKey", fk);
                }
              }
            }

            if (!pfFooterKeyCols.isEmpty()) {
              ArrayNode arr = om.createArrayNode();
              for (String p : pfFooterKeyCols.getOrDefault(0, Collections.emptySet()))
                arr.add(p);
              encNode.set("pfFooterKeyColumns", arr); // test doesn't depend on this
            }

            if (pf != null) {
              if (pf.algorithm != null) {
                algorithm = pf.algorithm; // ensure algorithm is set for PF
              }
              supplyAadPrefixFlag = pf.supplyAadPrefix;
              hasStoredAadPrefix = pf.aadPrefixBytes != null;
              if (pf.aadPrefixBytes != null)
                storedAadPrefixHex = toHex(pf.aadPrefixBytes);
              hasFooterKeyMetadata = pf.footerSigningKeyMetadata != null && pf.footerSigningKeyMetadata.length > 0;
              if (hasFooterKeyMetadata)
                footerKeyIdUtf8 = safeDecodeUtf8(pf.footerSigningKeyMetadata);

              if (pf.colKeys != null && !pf.colKeys.isEmpty()) {
                boolean hasAnyColumnKey = false;
                for (ColKeyMeta k : pf.colKeys) {
                  if (!k.encryptedWithFooterKey) {
                    hasAnyColumnKey = true;
                    break;
                  }
                }
                if (hasAnyColumnKey) {
                  ArrayNode colKeyArr = om.createArrayNode();
                  for (ColKeyMeta k : pf.colKeys) {
                    if (k.encryptedWithFooterKey)
                      continue;
                    ObjectNode kj = om.createObjectNode();
                    kj.put("rowGroup", k.rowGroupIndex);
                    kj.put("path", k.columnPath);
                    kj.put("encryptedWithFooterKey", false);
                    kj.put("columnKeyId", k.keyIdUtf8 != null ? k.keyIdUtf8 : null);
                    kj.put("columnKeyIdHex", toHex(k.keyMetadataBytes));
                    colKeyArr.add(kj);
                  }
                  if (colKeyArr.size() > 0) {
                    anyColumnKeyMetadata = true;
                    encNode.set("columnKeyMetadataPF", colKeyArr);
                  }
                }
              }
            }
          }

          // If we opened without decryptors but needed them, escalate
          if (needDecrypt && cand.props == null) {
            throw new NeedDecryptRetry();
          }

          // EF tail analysis (algo + AAD flags)
          if (cryptoTail != null) {
            final EncryptionAlgorithm alg = cryptoTail.getEncryption_algorithm();
            if (alg != null) {
              if (alg.isSetAES_GCM_V1()) {
                algorithm = "AES_GCM_V1";
                try {
                  byte[] bb = alg.getAES_GCM_V1().getAad_prefix();
                  if (bb != null && bb.length > 0) {
                    hasStoredAadPrefix = true;
                    storedAadPrefixHex = toHex(bb);
                  }
                } catch (Throwable ignore) {
                }
                supplyAadPrefixFlag = alg.getAES_GCM_V1().isSupply_aad_prefix();
              } else if (alg.isSetAES_GCM_CTR_V1()) {
                algorithm = "AES_GCM_CTR_V1";
                try {
                  byte[] bb = alg.getAES_GCM_CTR_V1().getAad_prefix();
                  if (bb != null && bb.length > 0) {
                    hasStoredAadPrefix = true;
                    storedAadPrefixHex = toHex(bb);
                  }
                } catch (Throwable ignore) {
                }
                supplyAadPrefixFlag = alg.getAES_GCM_CTR_V1().isSupply_aad_prefix();
              }
            }

            // Footer key metadata (EF)
            try {
              java.lang.reflect.Method isSetKM = cryptoTail.getClass().getMethod("isSetKey_metadata");
              Object v = isSetKM.invoke(cryptoTail);
              if (v instanceof Boolean && (Boolean) v) {
                hasFooterKeyMetadata = true;
                try {
                  java.lang.reflect.Method getKM = cryptoTail.getClass().getMethod("getKey_metadata");
                  Object val = getKM.invoke(cryptoTail);
                  byte[] b = null;
                  if (val instanceof java.nio.ByteBuffer) {
                    java.nio.ByteBuffer dup = ((java.nio.ByteBuffer) val).duplicate();
                    b = new byte[dup.remaining()];
                    dup.get(b);
                  } else if (val instanceof byte[]) {
                    b = (byte[]) val;
                  }
                  if (b != null)
                    footerKeyIdUtf8 = safeDecodeUtf8(b);
                } catch (Throwable ignore) {
                }
              }
            } catch (Throwable ignore) {
            }
          }

          // Encountered key IDs (when decryptors available)
          if (!encounteredKeyIds.isEmpty()) {
            ArrayNode ids = om.createArrayNode();
            for (String s : encounteredKeyIds)
              ids.add(s);
            encNode.set("encounteredColumnKeyIds", ids);
            anyColumnKeyMetadata = true;
          }

          // EF: prefer inline detection; fall back to probe only if empty
          if (ef && cand.footerKeyBytes != null) {
            Set<String> fkCols = efFkColsInline;
            if (fkCols.isEmpty()) {
              fkCols = detectEfFooterKeyColumns(input, cand.footerKeyBytes, aadPrefix); // your existing helper
            }
            ArrayNode arr = om.createArrayNode();
            for (String p : fkCols)
              arr.add(p);
            encNode.set("efFooterKeyColumns", arr);
            anyEncryptedWithFooterKey = anyEncryptedWithFooterKey || !fkCols.isEmpty();

            // Also use this to finalize layout for EF
            String inferredLayout = "partial";
            if (!fkCols.isEmpty() && rgArray.size() > 0) {
              ArrayNode cols0 = (ArrayNode) ((ObjectNode) rgArray.get(0)).get("columns");
              int fk0 = 0, total0 = cols0.size();
              for (int j = 0; j < total0; j++) {
                if (((ObjectNode) cols0.get(j)).has("encryptedWithFooterKey")
                    && ((ObjectNode) cols0.get(j)).get("encryptedWithFooterKey").asBoolean()) {
                  fk0++;
                }
              }
              if (fk0 == total0 && total0 > 0)
                inferredLayout = "uniform";
            }
            encNode.put("inferredLayout", inferredLayout);
          }
          // Inference
          String inferredLayout;
          if ("ENCRYPTED_FOOTER".equals(footerMode)) {
            inferredLayout = "partial"; // may be corrected to uniform below
            if (rgArray.size() > 0) {
              ArrayNode cols0 = (ArrayNode) ((ObjectNode) rgArray.get(0)).get("columns");
              int fk0 = 0;
              int total0 = cols0.size();
              for (int j = 0; j < cols0.size(); j++) {
                var node = (ObjectNode) cols0.get(j);
                if (node.has("encryptedWithFooterKey") && node.get("encryptedWithFooterKey").asBoolean())
                  fk0++;
              }
              if (fk0 == total0 && total0 > 0)
                inferredLayout = "uniform";
            }
          } else { // PLAINTEXT_FOOTER
            String inferredLayoutTmp = null;

            if (rgArray.size() > 0) {
              ArrayNode cols0 = (ArrayNode) ((ObjectNode) rgArray.get(0)).get("columns");
              int total0 = cols0.size();
              int fk0 = 0;
              int encNotFooterKey0 = 0;

              for (int j = 0; j < total0; j++) {
                ObjectNode node = (ObjectNode) cols0.get(j);
                boolean isEnc = node.has("isEncrypted") && node.get("isEncrypted").asBoolean();
                boolean isFk = node.has("encryptedWithFooterKey") && node.get("encryptedWithFooterKey").asBoolean();
                if (isFk)
                  fk0++;
                else if (isEnc)
                  encNotFooterKey0++;
              }

              if (fk0 == 0 && encNotFooterKey0 == 0) {
                inferredLayoutTmp = "plaintext";
              } else if (fk0 == total0) {
                inferredLayoutTmp = "uniform";
              } else {
                inferredLayoutTmp = "partial";
              }
            }

            // Fallback to old heuristic if for some reason PF metadata wasn't available
            inferredLayout = inferredLayoutTmp != null
                ? inferredLayoutTmp
                : (encryptedColumns == 0 ? "plaintext"
                    : (plaintextColumns == 0 && !anyColumnKeyMetadata ? "uniform" : "partial"));
          }

          String inferredAadMode;
          if (!hasStoredAadPrefix && !supplyAadPrefixFlag)
            inferredAadMode = "none";
          else if (hasStoredAadPrefix && !supplyAadPrefixFlag)
            inferredAadMode = "stored";
          else
            inferredAadMode = "supply";

          boolean footerSigned = "ENCRYPTED_FOOTER".equals(footerMode) || (encryptedColumns > 0);

          boolean aadPrefixMatchesSupplied = false;
          if (hasStoredAadPrefix && storedAadPrefixHex != null && aadPrefix != null) {
            aadPrefixMatchesSupplied = storedAadPrefixHex.equalsIgnoreCase(toHex(aadPrefix));
          }

          // Build encryption node
          encNode.put("type", footerMode);
          encNode.put("footerMode", footerMode);
          encNode.put("algorithm", algorithm);
          encNode.put("createdBy", String.valueOf(pread.getFileMetaData().getCreatedBy()));
          encNode.put("supplyAadPrefixFlag", supplyAadPrefixFlag);
          encNode.put("aadSuppliedAtRead", aadPrefix != null);
          encNode.put("hasStoredAadPrefix", hasStoredAadPrefix);
          if (hasStoredAadPrefix)
            encNode.put("storedAadPrefixHex", storedAadPrefixHex);
          encNode.put("aadPrefixMatchesSupplied", aadPrefixMatchesSupplied);
          encNode.put("hasFooterKeyId", hasFooterKeyMetadata);
          if (hasFooterKeyMetadata)
            encNode.put("footerKeyId", footerKeyIdUtf8);
          encNode.put("inferredLayout", inferredLayout);
          encNode.put("inferredAadMode", inferredAadMode);
          encNode.put("footerSigned", footerSigned);

          if (cand.footerKeyBytes != null) {
            encNode.put("footerKeyLengthBits", cand.footerKeyBytes.length * 8);
          }

          scanSucceeded = true;
        } catch (NeedDecryptRetry retry) {
          // try next candidate
        } finally {
          closeQuiet(pread);
        }
        if (scanSucceeded)
          break;
      }

      if (!scanSucceeded) {
        throw new IllegalArgumentException(
            "Could not scan file; decryption required but no candidate key worked (or vendor decryptor missing).");
      }

      out.put("file", fileArg);
      out.set("encryption", encNode);
      out.set("rowGroups", rgArray);

      ObjectNode totals = om.createObjectNode();
      totals.put("rowGroups", rgArray.size());
      totals.put("rowCount", totalRows);
      totals.put("columnsSeen", totalColumnsSeen);
      totals.put("encryptedColumns", encryptedColumns);
      totals.put("plaintextColumns", plaintextColumns);
      totals.put("anyColumnKeyMetadata", anyColumnKeyMetadata);
      totals.put("anyEncryptedWithFooterKey", anyEncryptedWithFooterKey);
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
        System.out.println(om2.writerWithDefaultPrettyPrinter().writeValueAsString(err));
      } catch (Exception ignore) {
        System.err.println("Fatal: " + t);
      }
    }
    System.exit(exit);
  }

  // ----- Helpers -----

  private static DecCand buildFooterProps(byte[] userKey, byte[] footerKey, byte[] aadPrefix,
      Set<String> encounteredCollector) {
    DecryptionKeyRetriever retr = new DecryptionKeyRetriever() {
      @Override
      public byte[] getKey(byte[] keyMetadata) {
        if (keyMetadata == null)
          return null;
        String id = safeDecodeUtf8(keyMetadata);
        if (id != null && encounteredCollector != null) {
          encounteredCollector.add(id);
        }
        // Generic case: only footer key known here
        return "kf".equals(id) ? footerKey : null;
      }
    };

    FileDecryptionProperties.Builder b = FileDecryptionProperties.builder()
        .withFooterKey(footerKey)
        .withKeyRetriever(retr);

    if (aadPrefix != null && aadPrefix.length > 0)
      b = b.withAADPrefix(aadPrefix);
    return new DecCand(b.build(), footerKey);
  }

  private static boolean isNullDecryptor(ParquetCryptoRuntimeException e) {
    String m = String.valueOf(e.getMessage());
    return m != null && m.contains("Null File Decryptor");
  }

  private static void closeQuiet(ParquetFileReader r) {
    if (r != null)
      try {
        r.close();
      } catch (Exception ignore) {
      }
  }

  private static boolean looksLikeRawAesHex(String s) {
    if (s == null)
      return false;
    int n = s.length();
    if (!(n == 32 || n == 48 || n == 64))
      return false;
    for (int i = 0; i < n; i++) {
      char c = s.charAt(i);
      boolean hex = (c >= '0' && c <= '9')
          || (c >= 'a' && c <= 'f')
          || (c >= 'A' && c <= 'F');
      if (!hex)
        return false;
    }
    return true;
  }

  private static byte[] hexToBytes(String s) {
    if ((s.length() & 1) != 0)
      throw new IllegalArgumentException("Odd hex length");
    int n = s.length() / 2;
    byte[] out = new byte[n];
    for (int i = 0; i < n; i++) {
      int hi = Character.digit(s.charAt(2 * i), 16);
      int lo = Character.digit(s.charAt(2 * i + 1), 16);
      if (hi < 0 || lo < 0)
        throw new IllegalArgumentException("Invalid hex");
      out[i] = (byte) ((hi << 4) | lo);
    }
    return out;
  }

  private static String toHex(byte[] bytes) {
    if (bytes == null)
      return null;
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes)
      sb.append(String.format("%02x", b));
    return sb.toString();
  }

  private static String safeDecodeUtf8(byte[] bytes) {
    try {
      return new String(bytes, StandardCharsets.UTF_8);
    } catch (Throwable ignore) {
      return null;
    }
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

  // --- InputFile for local files ---
  static final class LocalInputFile implements InputFile {
    private final File file;

    LocalInputFile(File file) {
      this.file = file;
    }

    @Override
    public long getLength() {
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
        public int read(ByteBuffer bb) throws IOException {
          return ch.read(bb);
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
              throw new EOFException("Reached EOF");
            total += r;
          }
        }

        @Override
        public void readFully(ByteBuffer bb) throws IOException {
          int remaining = bb.remaining();
          byte[] tmp = new byte[remaining];
          readFully(tmp, 0, remaining);
          bb.put(tmp);
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

  // ---- EF tail reader (local) ----
  static FileCryptoMetaData readCryptoMetaLocal(File f) throws IOException {
    try (RandomAccessFile raf = new RandomAccessFile(f, "r")) {
      long len = raf.length();
      if (len < 8)
        throw new IOException("File too small");
      raf.seek(len - 8);
      int combinedLenLE = raf.readInt();
      int combinedLen = Integer.reverseBytes(combinedLenLE);
      int magic = raf.readInt();
      if (magic != 0x50415245)
        throw new IOException("Not an encrypted tail (PARE)");
      long tailStart = len - 8L - combinedLen;
      if (tailStart < 0)
        throw new IOException("Bad tail length");
      raf.seek(tailStart);

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
      final TIOStreamTransport transport = new TIOStreamTransport(is);
      TCompactProtocol proto = new TCompactProtocol(transport);
      FileCryptoMetaData crypto = new FileCryptoMetaData();
      crypto.read(proto);
      return crypto;
    } catch (TTransportException e) {
      throw new IOException("Thrift transport error", e);
    } catch (Exception e) {
      throw new IOException("Failed to read FileCryptoMetaData", e);
    }
  }

  // ---- PF footer reader (plaintext footer region only) ----
  static final class ColKeyMeta {
    int rowGroupIndex;
    String columnPath; // "a.b.c"
    boolean encryptedWithFooterKey;
    byte[] keyMetadataBytes; // null if footer key
    String keyIdUtf8; // best-effort UTF-8 decode
  }

  static final class PFMeta {
    String algorithm;
    byte[] aadPrefixBytes;
    boolean supplyAadPrefix;
    byte[] footerSigningKeyMetadata;
    java.util.List<ColKeyMeta> colKeys = new java.util.ArrayList<>();
  }

  private static String dot(java.util.List<String> path) {
    if (path == null || path.isEmpty())
      return "";
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < path.size(); i++) {
      if (i > 0)
        sb.append('.');
      sb.append(path.get(i));
    }
    return sb.toString();
  }

  static PFMeta readPlaintextFooterMetaLocal(File f) throws IOException {
    try (RandomAccessFile raf = new RandomAccessFile(f, "r")) {
      long len = raf.length();
      if (len < 8)
        return null;

      raf.seek(len - 8);
      int footerPlusSigLE = raf.readInt();
      int footerPlusSig = Integer.reverseBytes(footerPlusSigLE);
      int magic = raf.readInt();
      if (magic != 0x50415231)
        return null; // not PF

      int footerLen = footerPlusSig - 28; // 12B nonce + 16B tag
      if (footerLen <= 0)
        return null;

      long footerStart = len - 8L - footerPlusSig;
      raf.seek(footerStart);

      InputStream is = new InputStream() {
        long pos = footerStart;
        final long end = footerStart + footerLen;

        @Override
        public int read() throws IOException {
          if (pos >= end)
            return -1;
          raf.seek(pos++);
          return raf.read();
        }

        @Override
        public int read(byte[] b, int off, int l) throws IOException {
          if (pos >= end)
            return -1;
          int toRead = (int) Math.min(l, end - pos);
          raf.seek(pos);
          int r = raf.read(b, off, toRead);
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

      org.apache.parquet.format.FileMetaData fmd = new org.apache.parquet.format.FileMetaData();
      try {
        fmd.read(proto);
      } catch (Exception e) {
        throw new IOException("Failed to read PF FileMetaData", e);
      }

      PFMeta out = new PFMeta();
      if (fmd.isSetEncryption_algorithm()) {
        EncryptionAlgorithm ealg = fmd.getEncryption_algorithm();
        if (ealg.isSetAES_GCM_V1()) {
          out.algorithm = "AES_GCM_V1";
          if (ealg.getAES_GCM_V1().isSetAad_prefix())
            out.aadPrefixBytes = ealg.getAES_GCM_V1().getAad_prefix();
          out.supplyAadPrefix = ealg.getAES_GCM_V1().isSetSupply_aad_prefix()
              && ealg.getAES_GCM_V1().isSupply_aad_prefix();
        } else if (ealg.isSetAES_GCM_CTR_V1()) {
          out.algorithm = "AES_GCM_CTR_V1";
          if (ealg.getAES_GCM_CTR_V1().isSetAad_prefix())
            out.aadPrefixBytes = ealg.getAES_GCM_CTR_V1().getAad_prefix();
          out.supplyAadPrefix = ealg.getAES_GCM_CTR_V1().isSetSupply_aad_prefix()
              && ealg.getAES_GCM_CTR_V1().isSupply_aad_prefix();
        }
      }

      // per-column crypto
      java.util.List<org.apache.parquet.format.RowGroup> rgs = fmd.getRow_groups();
      if (rgs != null) {
        for (int rgIdx = 0; rgIdx < rgs.size(); rgIdx++) {
          org.apache.parquet.format.RowGroup rg = rgs.get(rgIdx);
          java.util.List<org.apache.parquet.format.ColumnChunk> cols = rg.getColumns();
          if (cols == null)
            continue;
          for (org.apache.parquet.format.ColumnChunk cc : cols) {
            if (!cc.isSetCrypto_metadata())
              continue;
            org.apache.parquet.format.ColumnCryptoMetaData cmeta = cc.getCrypto_metadata();
            ColKeyMeta rec = new ColKeyMeta();
            rec.rowGroupIndex = rgIdx;
            if (cc.isSetMeta_data() && cc.getMeta_data().isSetPath_in_schema()) {
              rec.columnPath = dot(cc.getMeta_data().getPath_in_schema());
            }
            boolean withFooterKey = false;
            byte[] keyMeta = null;
            try {
              withFooterKey = cmeta.isSetENCRYPTION_WITH_FOOTER_KEY();
            } catch (Throwable ignore) {
            }
            if (!withFooterKey) {
              try {
                if (cmeta.isSetENCRYPTION_WITH_COLUMN_KEY()) {
                  var ewck = cmeta.getENCRYPTION_WITH_COLUMN_KEY();
                  if (ewck != null && ewck.isSetKey_metadata())
                    keyMeta = ewck.getKey_metadata();
                }
              } catch (Throwable ignore) {
              }
            }
            rec.encryptedWithFooterKey = withFooterKey;
            rec.keyMetadataBytes = keyMeta;
            if (keyMeta != null && keyMeta.length > 0)
              rec.keyIdUtf8 = safeDecodeUtf8(keyMeta);
            out.colKeys.add(rec);
          }
        }
      }

      if (fmd.isSetFooter_signing_key_metadata()) {
        out.footerSigningKeyMetadata = fmd.getFooter_signing_key_metadata();
      }
      return out;
    }
  }

  private static final class NeedDecryptRetry extends RuntimeException {
    private static final long serialVersionUID = 1L;
  }

  private static final class DecCand {
    final FileDecryptionProperties props; // may be null
    final byte[] footerKeyBytes; // null for plaintext try

    DecCand(FileDecryptionProperties props, byte[] footerKeyBytes) {
      this.props = props;
      this.footerKeyBytes = footerKeyBytes;
    }
  }

  private static Set<String> detectEfFooterKeyColumns(InputFile input, byte[] footerKey, byte[] aadPrefix) {
    Set<String> footerKeyCols = new LinkedHashSet<>();
    FileDecryptionProperties.Builder b = FileDecryptionProperties.builder().withFooterKey(footerKey);
    if (aadPrefix != null && aadPrefix.length > 0) {
      b = b.withAADPrefix(aadPrefix);
    }
    ParquetReadOptions opts = ParquetReadOptions.builder().withDecryption(b.build()).build();

    try (ParquetFileReader r = ParquetFileReader.open(input, opts)) {
      List<BlockMetaData> blocks = r.getFooter().getBlocks();
      for (BlockMetaData rg : blocks) {
        for (ColumnChunkMetaData c : rg.getColumns()) {
          boolean ok = true;
          try {
            // Touch fields that require decrypting column-chunk metadata with the *footer
            // key only*.
            // If this succeeds, that column is decryptable with the footer key.
            c.getPrimitiveType().getPrimitiveTypeName();
            c.getCodec();
          } catch (Throwable t) {
            ok = false; // likely uses a column key (or otherwise not footer-key-decryptable)
          }
          if (ok) {
            footerKeyCols.add(c.getPath().toDotString());
          }
        }
      }
    } catch (Throwable ignore) {
      // best effort
    }
    return footerKeyCols;
  }
}
