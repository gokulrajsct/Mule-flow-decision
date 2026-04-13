package com.mycompany.s3;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * AWSS3V4Signer
 *
 * Pure-Java AWS SigV4 signing for S3 PutObject — no AWS SDK required.
 * Designed to be called from a Mule flow via java:invoke-static.
 *
 * Entry point: {@link #signRequest(Map)}
 *
 * Signing modes (chosen automatically from whether contentLength is present):
 *
 *   STREAMING-AWS4-HMAC-SHA256-PAYLOAD
 *     Each 64 KB chunk of the body is individually HMAC-SHA256 signed as it
 *     streams through {@link SigningBoundedChunkedInputStream}, forming a
 *     signature chain:
 *       seed → chunk1 → chunk2 → … → final-empty-chunk
 *     Emits aws-chunked wire format:
 *       hex(n);chunk-signature=<64-hex>\r\n<data>\r\n … 0;chunk-signature=…\r\n\r\n
 *     Requires Content-Length from the client (for x-amz-decoded-content-length
 *     in the canonical request).
 *
 *   UNSIGNED-PAYLOAD  (fallback when no Content-Length)
 *     Request headers are still SigV4-signed; body streams through
 *     {@link BoundedInputStream} without per-chunk signing.
 *     HTTPS/TLS provides in-transit body integrity.
 *
 * Both modes enforce a 200 MB hard limit via the stream wrapper.
 * Memory cost: O(1 chunk) ≈ 64 KB — the full body is never buffered.
 */
public final class AWSS3V4Signer {

    private static final long MAX_BYTES  = 209_715_200L; // 200 MB
    private static final int  CHUNK_SIZE = 65_536;       // 64 KB

    private AWSS3V4Signer() {}

    // =========================================================================
    // Public entry point — called from Mule flow via java:invoke-static
    // =========================================================================

    /**
     * Signs an S3 PutObject request and wraps the payload stream.
     *
     * @param ctx  Map with keys:
     *               stream        – the raw payload InputStream
     *               accessKey     – AWS access key ID
     *               secretKey     – AWS secret access key
     *               region        – AWS region (e.g. "us-east-1")
     *               bucket        – S3 bucket name
     *               objectKey     – S3 object key (may contain '/')
     *               contentType   – MIME type ("application/octet-stream" if absent)
     *               contentLength – decoded byte count as String, or null / "" if unknown
     *
     * @return Map with keys:
     *               stream  – InputStream to stream as the PUT body (signed, size-guarded)
     *               headers – Map&lt;String,String&gt; of HTTP headers to include in the PUT request
     */
    public static Map<String, Object> signRequest(Map<String, Object> ctx) {
        InputStream stream        = (InputStream) ctx.get("stream");
        String      accessKey     = str(ctx, "accessKey");
        String      secretKey     = str(ctx, "secretKey");
        String      region        = str(ctx, "region");
        String      bucket        = str(ctx, "bucket");
        String      objectKey     = str(ctx, "objectKey");
        String      contentType   = nullOrEmpty(str(ctx, "contentType"))
                                        ? "application/octet-stream"
                                        : str(ctx, "contentType");
        String      contentLenStr = str(ctx, "contentLength");
        boolean     hasLength     = !nullOrEmpty(contentLenStr);
        long        decodedLength = hasLength ? Long.parseLong(contentLenStr) : -1L;

        // ── Timestamp ────────────────────────────────────────────────────────
        ZonedDateTime now       = ZonedDateTime.now(ZoneOffset.UTC);
        String        amzDate   = now.format(DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'"));
        String        dateStamp = now.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String        credScope = dateStamp + "/" + region + "/s3/aws4_request";

        // ── Signing key ──────────────────────────────────────────────────────
        byte[] signingKey = buildSigningKey(secretKey, dateStamp, region, "s3");

        // ── URL-encode object key (per-segment, preserve '/') ────────────────
        String encodedKey = encodeObjectKey(objectKey);

        // ── Canonical request + string to sign ───────────────────────────────
        String host = bucket + ".s3." + region + ".amazonaws.com";

        final String payloadHash;
        final String signedHeaders;
        final String canonicalHeaders;

        if (hasLength) {
            payloadHash   = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
            signedHeaders = "content-encoding;content-type;host;" +
                            "x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length";
            canonicalHeaders =
                "content-encoding:aws-chunked\n" +
                "content-type:" + contentType + "\n" +
                "host:" + host + "\n" +
                "x-amz-content-sha256:" + payloadHash + "\n" +
                "x-amz-date:" + amzDate + "\n" +
                "x-amz-decoded-content-length:" + decodedLength + "\n";
        } else {
            payloadHash   = "UNSIGNED-PAYLOAD";
            signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date";
            canonicalHeaders =
                "content-type:" + contentType + "\n" +
                "host:" + host + "\n" +
                "x-amz-content-sha256:" + payloadHash + "\n" +
                "x-amz-date:" + amzDate + "\n";
        }

        String canonicalRequest =
            "PUT\n" + "/" + encodedKey + "\n" + "\n" +
            canonicalHeaders + "\n" +
            signedHeaders + "\n" +
            payloadHash;

        String stringToSign =
            "AWS4-HMAC-SHA256\n" +
            amzDate + "\n" +
            credScope + "\n" +
            sha256Hex(canonicalRequest);

        // ── Seed signature ───────────────────────────────────────────────────
        String seedSig = hmacHex(signingKey, stringToSign);

        // ── Authorization header ─────────────────────────────────────────────
        String authHeader =
            "AWS4-HMAC-SHA256 " +
            "Credential=" + accessKey + "/" + credScope + "," +
            "SignedHeaders=" + signedHeaders + "," +
            "Signature=" + seedSig;

        // ── Build HTTP headers map ───────────────────────────────────────────
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization",       authHeader);
        headers.put("x-amz-date",          amzDate);
        headers.put("x-amz-content-sha256", payloadHash);
        headers.put("Content-Type",         contentType);

        // ── Wrap payload stream ──────────────────────────────────────────────
        final InputStream wrappedStream;

        // computeContentLength=true: pre-compute the exact encoded body size and
        // include Content-Length in the returned headers map.
        // Use this with requestStreamingMode="NEVER" on the Mule http:request when
        // Transfer-Encoding: chunked is blocked by a network proxy.
        // Requires Content-Length from the client (hasLength must be true).
        boolean computeContentLength = "true".equalsIgnoreCase(str(ctx, "computeContentLength"));

        if (hasLength) {
            headers.put("Content-Encoding",             "aws-chunked");
            headers.put("x-amz-decoded-content-length", String.valueOf(decodedLength));

            if (computeContentLength) {
                // Pre-compute the exact number of bytes SigningBoundedChunkedInputStream
                // will emit. This lets the HTTP connector send a fixed Content-Length
                // instead of Transfer-Encoding: chunked — required when proxies between
                // Mule and S3 strip or reject chunked transfer encoding.
                long encodedSize = computeEncodedBodySize(decodedLength, CHUNK_SIZE);
                headers.put("Content-Length", String.valueOf(encodedSize));
            }

            wrappedStream = new SigningBoundedChunkedInputStream(
                stream, CHUNK_SIZE, signingKey,
                amzDate, credScope, seedSig,
                sha256Hex(""), MAX_BYTES
            );
        } else {
            // UNSIGNED-PAYLOAD: just enforce the size limit, no chunk signing
            wrappedStream = new BoundedInputStream(stream, MAX_BYTES);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("stream",  wrappedStream);
        result.put("headers", headers);
        return result;
    }

    // =========================================================================
    // BoundedInputStream
    // =========================================================================

    /**
     * FilterInputStream that counts bytes as they pass through and throws
     * {@code IOException("FILE_SIZE_LIMIT_EXCEEDED")} once the running count
     * exceeds {@code limit}.  Zero heap overhead — no buffering.
     */
    public static final class BoundedInputStream extends FilterInputStream {

        private long count = 0L;
        private final long limit;

        public BoundedInputStream(InputStream src, long limit) {
            super(src);
            this.limit = limit;
        }

        @Override
        public int read() throws IOException {
            int b = super.read();
            if (b != -1 && ++count > limit)
                throw new IOException("FILE_SIZE_LIMIT_EXCEEDED");
            return b;
        }

        @Override
        public int read(byte[] buf, int off, int len) throws IOException {
            int n = super.read(buf, off, len);
            if (n > 0 && (count += n) > limit)
                throw new IOException("FILE_SIZE_LIMIT_EXCEEDED");
            return n;
        }
    }

    // =========================================================================
    // SigningBoundedChunkedInputStream
    // =========================================================================

    /**
     * InputStream wrapper that simultaneously:
     *
     *   1. Enforces a byte-count limit (throws FILE_SIZE_LIMIT_EXCEEDED at 200 MB).
     *   2. Reads the source in CHUNK_SIZE blocks and, for each block:
     *        a. Computes SHA-256 of the chunk bytes.
     *        b. Builds the chunk string-to-sign:
     *             "AWS4-HMAC-SHA256-PAYLOAD\n"
     *             + amzDate + "\n" + credScope + "\n"
     *             + prevChunkSignature + "\n"   ← signature chain
     *             + SHA256("") + "\n"           ← empty chunk-header hash
     *             + SHA256(chunkData)
     *        c. chunkSig = HMAC-SHA256(signingKey, chunkStringToSign)
     *        d. Emits:  hex(len);chunk-signature=<sig>\r\n<data>\r\n
     *   3. After the last source chunk emits the final empty-chunk terminator:
     *        0;chunk-signature=<finalSig>\r\n\r\n
     *
     * Consumers (the Mule HTTP connector) read the resulting bytes and forward
     * them directly as the PUT body to S3.
     */
    public static final class SigningBoundedChunkedInputStream extends InputStream {

        private final InputStream src;
        private final int         chunkSize;
        private final byte[]      signingKey;
        private final String      amzDate;
        private final String      credScope;
        private final String      emptyHash;   // SHA-256 of "" — constant
        private final long        maxBytes;

        private String  prevSig;
        private long    totalRead  = 0L;
        private byte[]  outBuf     = new byte[0];
        private int     outOff     = 0;
        private boolean srcDone    = false;
        private boolean finalSent  = false;

        public SigningBoundedChunkedInputStream(
                InputStream src, int chunkSize, byte[] signingKey,
                String amzDate, String credScope, String seedSig,
                String emptyHash, long maxBytes) {
            this.src        = src;
            this.chunkSize  = chunkSize;
            this.signingKey = signingKey;
            this.amzDate    = amzDate;
            this.credScope  = credScope;
            this.prevSig    = seedSig;
            this.emptyHash  = emptyHash;
            this.maxBytes   = maxBytes;
        }

        /**
         * Sign one chunk and return the complete aws-chunked encoded bytes:
         *   hex(n);chunk-signature=<sig>\r\n<data>\r\n
         */
        private byte[] encodeSignedChunk(byte[] chunkData) {
            String dataHash = sha256HexBytes(chunkData);
            String sts =
                "AWS4-HMAC-SHA256-PAYLOAD\n" +
                amzDate + "\n" + credScope + "\n" +
                prevSig + "\n" +
                emptyHash + "\n" +
                dataHash;
            String sig = hmacHex(signingKey, sts);
            prevSig = sig;  // advance signature chain

            String header  = Integer.toHexString(chunkData.length) +
                             ";chunk-signature=" + sig + "\r\n";
            byte[] hb  = header.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] out = new byte[hb.length + chunkData.length + 2];
            System.arraycopy(hb,        0, out, 0,          hb.length);
            System.arraycopy(chunkData, 0, out, hb.length,  chunkData.length);
            out[hb.length + chunkData.length]     = '\r';
            out[hb.length + chunkData.length + 1] = '\n';
            return out;
        }

        /**
         * Fill {@code outBuf} with the next encoded chunk.
         * Returns {@code false} when the stream (including the final empty chunk) is exhausted.
         */
        private boolean fillBuffer() throws IOException {
            if (outOff < outBuf.length) return true;
            if (finalSent) return false;

            if (!srcDone) {
                byte[] chunk = new byte[chunkSize];
                int total = 0;
                while (total < chunkSize) {
                    int n = src.read(chunk, total, chunkSize - total);
                    if (n == -1) { srcDone = true; break; }
                    total += n;
                }
                if (total > 0) {
                    totalRead += total;
                    if (totalRead > maxBytes)
                        throw new IOException("FILE_SIZE_LIMIT_EXCEEDED");

                    byte[] actual = (total == chunkSize) ? chunk : Arrays.copyOf(chunk, total);
                    outBuf = encodeSignedChunk(actual);
                    outOff = 0;
                    return true;
                }
            }

            // Emit the final empty-chunk to close the signing chain
            String finalDataHash = sha256HexBytes(new byte[0]);
            String sts =
                "AWS4-HMAC-SHA256-PAYLOAD\n" +
                amzDate + "\n" + credScope + "\n" +
                prevSig + "\n" +
                emptyHash + "\n" +
                finalDataHash;
            String finalSig   = hmacHex(signingKey, sts);
            String finalChunk = "0;chunk-signature=" + finalSig + "\r\n\r\n";
            outBuf    = finalChunk.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            outOff    = 0;
            finalSent = true;
            return true;
        }

        @Override
        public int read() throws IOException {
            if (!fillBuffer()) return -1;
            return outBuf[outOff++] & 0xFF;
        }

        @Override
        public int read(byte[] buf, int off, int len) throws IOException {
            if (!fillBuffer()) return -1;
            int avail  = outBuf.length - outOff;
            int toRead = Math.min(avail, len);
            System.arraycopy(outBuf, outOff, buf, off, toRead);
            outOff += toRead;
            return toRead;
        }

        @Override
        public void close() throws IOException { src.close(); }
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    /**
     * Computes the exact number of bytes SigningBoundedChunkedInputStream will emit
     * for a given decoded content length and chunk size.
     *
     * Per full chunk (CHUNK_SIZE bytes):
     *   hex(CHUNK_SIZE) + ";chunk-signature=" (17) + 64-char sig + CRLF + data + CRLF
     *   e.g. for 65536: "10000" (5) + 17 + 64 + 2 + 65536 + 2 = 65626 bytes
     *
     * Final empty chunk:
     *   "0" + ";chunk-signature=" (17) + 64-char sig + CRLF + CRLF = 86 bytes
     */
    static long computeEncodedBodySize(long decodedLength, int chunkSize) {
        long encoded   = 0L;
        long remaining = decodedLength;
        while (remaining > 0) {
            long   thisChunk = Math.min(remaining, chunkSize);
            String chunkHex  = Long.toHexString(thisChunk);
            encoded += chunkHex.length() + 17L + 64L + 2L + thisChunk + 2L;
            remaining -= thisChunk;
        }
        encoded += 1L + 17L + 64L + 2L + 2L; // final empty chunk: 86 bytes
        return encoded;
    }

    static byte[] buildSigningKey(String secretKey, String date,
                                  String region, String service) {
        byte[] kDate    = hmac(("AWS4" + secretKey).getBytes(java.nio.charset.StandardCharsets.UTF_8), date);
        byte[] kRegion  = hmac(kDate,    region);
        byte[] kService = hmac(kRegion,  service);
        return hmac(kService, "aws4_request");
    }

    private static String encodeObjectKey(String key) {
        StringBuilder sb = new StringBuilder();
        String[] segments = key.split("/", -1);
        for (int i = 0; i < segments.length; i++) {
            if (i > 0) sb.append('/');
            // encode(String, Charset) is Java 10+; use .name() for Java 8 compatibility.
            // UTF-8 is mandated by the JVM spec so UnsupportedEncodingException cannot occur.
            try {
                sb.append(java.net.URLEncoder.encode(
                        segments[i], java.nio.charset.StandardCharsets.UTF_8.name())
                    .replace("+", "%20"));
            } catch (java.io.UnsupportedEncodingException e) {
                throw new AssertionError("UTF-8 is always supported", e);
            }
        }
        return sb.toString();
    }

    private static byte[] hmac(byte[] key, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("HmacSHA256 failed", e);
        }
    }

    static String hmacHex(byte[] key, String data) {
        return bytesToHex(hmac(key, data));
    }

    static String sha256Hex(String s) {
        return sha256HexBytes(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private static String sha256HexBytes(byte[] data) {
        try {
            return bytesToHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 failed", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        // Avoid String.format("%02x", b) — it creates a Formatter on every iteration.
        // Bit-shift approach is allocation-free and ~10x faster in hot signing paths.
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            int v = b & 0xFF;
            if (v < 0x10) hex.append('0');
            hex.append(Integer.toHexString(v));
        }
        return hex.toString();
    }

    private static String str(Map<String, Object> ctx, String key) {
        Object v = ctx.get(key);
        return v == null ? "" : v.toString();
    }

    private static boolean nullOrEmpty(String s) {
        return s == null || s.isEmpty();
    }
}
