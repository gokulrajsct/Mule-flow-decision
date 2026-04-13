package com.mycompany.s3;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.regions.Region;

import java.io.InputStream;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * AWSS3V4SignerSDK
 *
 * AWS SigV4 signing for S3 PutObject using software.amazon.awssdk.auth.*.
 * Contrast with AWSS3V4Signer which uses only JDK classes (no SDK dependency).
 *
 * SDK classes used:
 *   AwsBasicCredentials.create(accessKey, secretKey)
 *     Wraps the raw key pair as an SDK credential object.
 *     In production swap for DefaultCredentialsProvider.create().resolveCredentials()
 *     to automatically pick up IAM roles, env vars, ~/.aws/credentials, etc.
 *   Region.of(region)
 *     Validates the region string at startup; throws SdkClientException for unknown regions.
 *
 * Why the AWS SDK signing APIs are not used for SigV4 computation:
 *   The legacy Aws4Signer is deprecated.
 *   The replacement AwsV4HttpSigner (http-auth-aws module) exposes a signing SPI
 *   whose class names and builder API changed between 2.21–2.28 patch releases,
 *   making it unreliable to call directly from application code outside the SDK.
 *   Both signers also lack a public API for STREAMING-AWS4-HMAC-SHA256-PAYLOAD.
 *   The SigV4 algorithm itself is stable and simple; we call the shared helpers
 *   in AWSS3V4Signer (buildSigningKey, hmacHex, sha256Hex) that are tested and
 *   already in the classpath — zero duplication, no fragile SPI dependency.
 *
 * Two signing modes (selected automatically):
 *
 *   STREAMING-AWS4-HMAC-SHA256-PAYLOAD  [when contentLength is provided]
 *     Each 64 KB chunk is HMAC-SHA256 signed in-flight via
 *     SigningBoundedChunkedInputStream (reused from AWSS3V4Signer).
 *     Signature chain: seed → chunk1 → chunk2 → … → empty-chunk.
 *     Wire format: aws-chunked (hex(n);chunk-signature=<sig>\r\n<data>\r\n)
 *     Content-Length: pre-computed via computeEncodedBodySize() when
 *       computeContentLength=true — prevents Transfer-Encoding: chunked.
 *
 *   UNSIGNED-PAYLOAD  [fallback when contentLength is absent]
 *     Headers signed with standard SigV4; body is not per-chunk signed.
 *     Body integrity covered by TLS. BoundedInputStream enforces 200 MB cap.
 *
 * Memory cost: O(1 chunk) ≈ 64 KB — the full body is never buffered.
 * Size guard:  200 MB hard limit via BoundedInputStream / SigningBoundedChunkedInputStream.
 *
 * Entry point: {@link #signRequest(Map)} — called from Mule via java:invoke-static.
 */
public final class AWSS3V4SignerSDK {

    private static final long MAX_BYTES  = 209_715_200L; // 200 MB
    private static final int  CHUNK_SIZE = 65_536;       // 64 KB

    private AWSS3V4SignerSDK() {}

    // =========================================================================
    // Public entry point
    // =========================================================================

    /**
     * Signs an S3 PutObject request using AWS SDK v2 credential objects.
     *
     * @param ctx  Map with keys:
     *               stream               – raw payload InputStream
     *               accessKey            – AWS access key ID
     *               secretKey            – AWS secret access key
     *               region               – AWS region (e.g. "us-east-1")
     *               bucket               – S3 bucket name
     *               objectKey            – S3 object key (may contain '/')
     *               contentType          – MIME type ("application/octet-stream" if absent)
     *               contentLength        – decoded byte count as String, or null/""
     *               computeContentLength – "true" to pre-compute encoded body size and
     *                                      include Content-Length in headers (STREAMING mode)
     *
     * @return Map with keys:
     *               stream  – InputStream to stream as the PUT body (signed, size-guarded)
     *               headers – Map&lt;String,String&gt; of HTTP headers for the PUT request
     */
    public static Map<String, Object> signRequest(Map<String, Object> ctx) {

        // Accept InputStream (if passed directly from Java) or byte[] (if DataWeave
        // coerced the payload via "payload as Binary" — which is the Mule flow case).
        final Object    streamRaw = ctx.get("stream");
        final InputStream stream;
        if (streamRaw instanceof InputStream) {
            stream = (InputStream) streamRaw;
        } else if (streamRaw instanceof byte[]) {
            stream = new java.io.ByteArrayInputStream((byte[]) streamRaw);
        } else if (streamRaw != null) {
            // Mule 4 CursorStreamProvider — wrap lazily so the cursor is opened
            // on the first read() call (during http:request body transfer), NOT here.
            // Opening the cursor inside the Groovy scripting component causes Mule to
            // close it when that component finishes, producing "Stream is closed" at
            // the request connector. Lazy opening keeps the cursor alive throughout
            // the http:request component's execution where it is actually consumed.
            stream = new LazyCursorInputStream(streamRaw);
        } else {
            throw new IllegalArgumentException("ctx['stream'] must not be null");
        }
        String      accessKey       = str(ctx, "accessKey");
        String      secretKey       = str(ctx, "secretKey");
        String      region          = str(ctx, "region");
        String      bucket          = str(ctx, "bucket");
        String      objectKey       = str(ctx, "objectKey");
        String      contentType     = nullOrEmpty(str(ctx, "contentType"))
                                          ? "application/octet-stream"
                                          : str(ctx, "contentType");
        String      contentLenStr   = str(ctx, "contentLength");
        boolean     hasLength       = !nullOrEmpty(contentLenStr);
        long        decodedLength   = hasLength ? Long.parseLong(contentLenStr) : -1L;
        boolean     computeContentLength = "true".equalsIgnoreCase(str(ctx, "computeContentLength"));

        // ── SDK credential object ────────────────────────────────────────────
        // AwsBasicCredentials wraps the raw key pair as an SDK-managed credential.
        // credentials.accessKeyId() / credentials.secretAccessKey() are used below
        // instead of the raw strings, keeping key material inside the SDK object.
        AwsBasicCredentials credentials = AwsBasicCredentials.create(accessKey, secretKey);

        // ── SDK region validation ────────────────────────────────────────────
        // Region.of() throws SdkClientException for unknown/malformed region strings,
        // catching misconfiguration at startup rather than at signing time.
        // region.id() returns the canonical lowercase region string used in signing.
        String canonicalRegion = Region.of(region).id();

        String encodedKey = encodeObjectKey(objectKey);
        String host       = bucket + ".s3." + canonicalRegion + ".amazonaws.com";

        if (hasLength) {
            return signStreaming(stream, credentials, canonicalRegion,
                                 host, encodedKey, contentType,
                                 decodedLength, computeContentLength);
        } else {
            return signUnsignedPayload(stream, credentials, canonicalRegion,
                                       host, encodedKey, contentType);
        }
    }

    // =========================================================================
    // STREAMING-AWS4-HMAC-SHA256-PAYLOAD mode
    // =========================================================================

    /**
     * Signs headers for STREAMING mode and wraps the body in
     * SigningBoundedChunkedInputStream for per-chunk payload signing.
     *
     * Signing key and Authorization header are computed using the shared
     * helpers in AWSS3V4Signer; credentials come from the SDK AwsBasicCredentials
     * object (credentials.secretAccessKey(), credentials.accessKeyId()).
     */
    private static Map<String, Object> signStreaming(
            InputStream stream,
            AwsBasicCredentials credentials,
            String region,
            String host,
            String encodedKey,
            String contentType,
            long   decodedLength,
            boolean computeContentLength) {

        // ── Timestamp ────────────────────────────────────────────────────────
        ZonedDateTime now       = ZonedDateTime.now(ZoneOffset.UTC);
        String        amzDate   = now.format(DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'"));
        String        dateStamp = now.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String        credScope = dateStamp + "/" + region + "/s3/aws4_request";

        // ── Signing key ──────────────────────────────────────────────────────
        // credentials.secretAccessKey() reads from the SDK credential object.
        // AWSS3V4Signer.buildSigningKey() performs the 4-step HMAC derivation.
        byte[] signingKey = AWSS3V4Signer.buildSigningKey(
                credentials.secretAccessKey(), dateStamp, region, "s3");

        // ── Canonical request ────────────────────────────────────────────────
        String payloadHash   = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
        String signedHeaders = "content-encoding;content-type;host;" +
                               "x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length";
        String canonicalHeaders =
            "content-encoding:aws-chunked\n" +
            "content-type:" + contentType + "\n" +
            "host:" + host + "\n" +
            "x-amz-content-sha256:" + payloadHash + "\n" +
            "x-amz-date:" + amzDate + "\n" +
            "x-amz-decoded-content-length:" + decodedLength + "\n";

        String canonicalRequest =
            "PUT\n" + "/" + encodedKey + "\n\n" +
            canonicalHeaders + "\n" +
            signedHeaders + "\n" +
            payloadHash;

        // ── String to sign ───────────────────────────────────────────────────
        String stringToSign =
            "AWS4-HMAC-SHA256\n" +
            amzDate + "\n" +
            credScope + "\n" +
            AWSS3V4Signer.sha256Hex(canonicalRequest);

        // ── Seed signature ───────────────────────────────────────────────────
        String seedSig = AWSS3V4Signer.hmacHex(signingKey, stringToSign);

        // ── Authorization header ─────────────────────────────────────────────
        // credentials.accessKeyId() reads the key ID from the SDK credential object.
        String authHeader =
            "AWS4-HMAC-SHA256 " +
            "Credential=" + credentials.accessKeyId() + "/" + credScope + "," +
            "SignedHeaders=" + signedHeaders + "," +
            "Signature=" + seedSig;

        // ── Headers map ──────────────────────────────────────────────────────
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization",                authHeader);
        headers.put("x-amz-date",                   amzDate);
        headers.put("x-amz-content-sha256",         payloadHash);
        headers.put("Content-Type",                  contentType);
        headers.put("Content-Encoding",              "aws-chunked");
        headers.put("x-amz-decoded-content-length",  String.valueOf(decodedLength));

        // Pre-compute the exact encoded body size so requestStreamingMode="NEVER"
        // sends a fixed Content-Length — no Transfer-Encoding: chunked emitted.
        if (computeContentLength) {
            long encodedSize = AWSS3V4Signer.computeEncodedBodySize(decodedLength, CHUNK_SIZE);
            headers.put("Content-Length", String.valueOf(encodedSize));
        }

        // ── Wrap stream in per-chunk signer ──────────────────────────────────
        // Each 64 KB chunk is HMAC-signed and emitted in aws-chunked wire format.
        InputStream wrappedStream = new AWSS3V4Signer.SigningBoundedChunkedInputStream(
                stream, CHUNK_SIZE, signingKey,
                amzDate, credScope, seedSig,
                AWSS3V4Signer.sha256Hex(""), MAX_BYTES);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("stream",  wrappedStream);
        result.put("headers", headers);
        return result;
    }

    // =========================================================================
    // UNSIGNED-PAYLOAD mode (fallback — no Content-Length)
    // =========================================================================

    /**
     * Signs headers with SigV4 using UNSIGNED-PAYLOAD as the canonical body hash.
     * No per-chunk signing — body integrity is provided by TLS.
     *
     * Same algorithm as AWSS3V4Signer's UNSIGNED-PAYLOAD path, but credentials
     * are read from the SDK AwsBasicCredentials object.
     */
    private static Map<String, Object> signUnsignedPayload(
            InputStream stream,
            AwsBasicCredentials credentials,
            String region,
            String host,
            String encodedKey,
            String contentType) {

        // ── Timestamp ────────────────────────────────────────────────────────
        ZonedDateTime now       = ZonedDateTime.now(ZoneOffset.UTC);
        String        amzDate   = now.format(DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'"));
        String        dateStamp = now.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String        credScope = dateStamp + "/" + region + "/s3/aws4_request";

        // ── Signing key ──────────────────────────────────────────────────────
        byte[] signingKey = AWSS3V4Signer.buildSigningKey(
                credentials.secretAccessKey(), dateStamp, region, "s3");

        // ── Canonical request ────────────────────────────────────────────────
        String payloadHash   = "UNSIGNED-PAYLOAD";
        String signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date";
        String canonicalHeaders =
            "content-type:" + contentType + "\n" +
            "host:" + host + "\n" +
            "x-amz-content-sha256:" + payloadHash + "\n" +
            "x-amz-date:" + amzDate + "\n";

        String canonicalRequest =
            "PUT\n" + "/" + encodedKey + "\n\n" +
            canonicalHeaders + "\n" +
            signedHeaders + "\n" +
            payloadHash;

        // ── String to sign ───────────────────────────────────────────────────
        String stringToSign =
            "AWS4-HMAC-SHA256\n" +
            amzDate + "\n" +
            credScope + "\n" +
            AWSS3V4Signer.sha256Hex(canonicalRequest);

        // ── Signature + Authorization header ─────────────────────────────────
        String signature  = AWSS3V4Signer.hmacHex(signingKey, stringToSign);
        String authHeader =
            "AWS4-HMAC-SHA256 " +
            "Credential=" + credentials.accessKeyId() + "/" + credScope + "," +
            "SignedHeaders=" + signedHeaders + "," +
            "Signature=" + signature;

        // ── Headers map ──────────────────────────────────────────────────────
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization",        authHeader);
        headers.put("x-amz-date",           amzDate);
        headers.put("x-amz-content-sha256", payloadHash);
        headers.put("Content-Type",          contentType);

        // ── Wrap stream with 200 MB size guard ───────────────────────────────
        InputStream wrappedStream = new AWSS3V4Signer.BoundedInputStream(stream, MAX_BYTES);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("stream",  wrappedStream);
        result.put("headers", headers);
        return result;
    }

    // =========================================================================
    // Header-only signing (no stream — avoids DataWeave coercion problem)
    // =========================================================================

    /**
     * Signs an S3 PutObject request using UNSIGNED-PAYLOAD mode and returns
     * only the HTTP headers. The raw payload is NOT passed through this method,
     * so DataWeave never coerces it. The caller passes {@code payload} directly
     * as the {@code http:body} in the Mule flow.
     *
     * <p>SignedHeaders: {@code content-type;host;x-amz-content-sha256;x-amz-date}
     * <p>Content-Length is returned as an unsigned header (key {@code "Content-Length"})
     * when {@code contentLength} is provided, so Mule can send it without signing it.
     *
     * @param ctx  Map with keys:
     *               accessKey     – AWS access key ID
     *               secretKey     – AWS secret access key
     *               region        – AWS region (e.g. "us-east-1")
     *               bucket        – S3 bucket name
     *               objectKey     – S3 object key (may contain '/')
     *               contentType   – MIME type ("application/octet-stream" if absent)
     *               contentLength – byte count as String, or null/"" (omits Content-Length header)
     *
     * @return Map&lt;String,String&gt; of HTTP headers ready for the PUT request
     */
    public static Map<String, String> signHeadersOnly(Map<String, Object> ctx) {
        String accessKey    = str(ctx, "accessKey");
        String secretKey    = str(ctx, "secretKey");
        String region       = str(ctx, "region");
        String bucket       = str(ctx, "bucket");
        String objectKey    = str(ctx, "objectKey");
        String contentType  = nullOrEmpty(str(ctx, "contentType"))
                                  ? "application/octet-stream"
                                  : str(ctx, "contentType");
        String contentLenStr = str(ctx, "contentLength");

        AwsBasicCredentials credentials   = AwsBasicCredentials.create(accessKey, secretKey);
        String              canonicalRegion = Region.of(region).id();
        String              encodedKey    = encodeObjectKey(objectKey);
        String              host          = bucket + ".s3." + canonicalRegion + ".amazonaws.com";

        ZonedDateTime now       = ZonedDateTime.now(ZoneOffset.UTC);
        String        amzDate   = now.format(DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'"));
        String        dateStamp = now.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String        credScope = dateStamp + "/" + canonicalRegion + "/s3/aws4_request";

        byte[] signingKey = AWSS3V4Signer.buildSigningKey(
                credentials.secretAccessKey(), dateStamp, canonicalRegion, "s3");

        String payloadHash   = "UNSIGNED-PAYLOAD";
        String signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date";
        String canonicalHeaders =
            "content-type:" + contentType + "\n" +
            "host:" + host + "\n" +
            "x-amz-content-sha256:" + payloadHash + "\n" +
            "x-amz-date:" + amzDate + "\n";

        String canonicalRequest =
            "PUT\n" + "/" + encodedKey + "\n\n" +
            canonicalHeaders + "\n" +
            signedHeaders + "\n" +
            payloadHash;

        String stringToSign =
            "AWS4-HMAC-SHA256\n" +
            amzDate + "\n" +
            credScope + "\n" +
            AWSS3V4Signer.sha256Hex(canonicalRequest);

        String signature  = AWSS3V4Signer.hmacHex(signingKey, stringToSign);
        String authHeader =
            "AWS4-HMAC-SHA256 " +
            "Credential=" + credentials.accessKeyId() + "/" + credScope + "," +
            "SignedHeaders=" + signedHeaders + "," +
            "Signature=" + signature;

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization",        authHeader);
        headers.put("x-amz-date",           amzDate);
        headers.put("x-amz-content-sha256", payloadHash);
        headers.put("Content-Type",         contentType);
        // Content-Length is NOT in SignedHeaders — Mule may adjust it during streaming.
        // It is returned as a plain (unsigned) header so the requester includes it.
        if (!nullOrEmpty(contentLenStr)) {
            headers.put("Content-Length", contentLenStr);
        }
        return headers;
    }

    // =========================================================================
    // Multipart Upload — header-only signing (virtual-hosted style)
    // =========================================================================

    /**
     * Delegates sha256Hex to AWSS3V4Signer — exposed for java:invoke-static
     * in the complete-multipart-subflow (body hash computation).
     */
    public static String sha256Hex(String data) {
        return AWSS3V4Signer.sha256Hex(data);
    }

    /**
     * Signs headers for POST /{key}?uploads — Initiate Multipart Upload.
     * ctx keys: accessKey, secretKey, region, bucket, objectKey, contentType
     */
    public static Map<String, String> signMultipartInitiate(Map<String, Object> ctx) {
        String accessKey   = str(ctx, "accessKey");
        String secretKey   = str(ctx, "secretKey");
        String region      = str(ctx, "region");
        String bucket      = str(ctx, "bucket");
        String objectKey   = str(ctx, "objectKey");
        String contentType = nullOrEmpty(str(ctx, "contentType"))
                                 ? "application/octet-stream" : str(ctx, "contentType");

        AwsBasicCredentials creds          = AwsBasicCredentials.create(accessKey, secretKey);
        String              canonicalRegion = Region.of(region).id();
        String              encodedKey     = encodeObjectKey(objectKey);
        String              host           = bucket + ".s3." + canonicalRegion + ".amazonaws.com";

        ZonedDateTime now       = ZonedDateTime.now(ZoneOffset.UTC);
        String        amzDate   = now.format(DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'"));
        String        dateStamp = now.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String        credScope = dateStamp + "/" + canonicalRegion + "/s3/aws4_request";

        byte[] signingKey = AWSS3V4Signer.buildSigningKey(
                creds.secretAccessKey(), dateStamp, canonicalRegion, "s3");

        String payloadHash   = "UNSIGNED-PAYLOAD";
        String signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date";
        String canonicalRequest =
            "POST\n" + "/" + encodedKey + "\nuploads=\n" +
            "content-type:" + contentType + "\n" +
            "host:" + host + "\n" +
            "x-amz-content-sha256:" + payloadHash + "\n" +
            "x-amz-date:" + amzDate + "\n\n" +
            signedHeaders + "\n" + payloadHash;

        String sig = AWSS3V4Signer.hmacHex(signingKey,
            "AWS4-HMAC-SHA256\n" + amzDate + "\n" + credScope + "\n" +
            AWSS3V4Signer.sha256Hex(canonicalRequest));

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization",
            "AWS4-HMAC-SHA256 Credential=" + creds.accessKeyId() + "/" + credScope +
            ",SignedHeaders=" + signedHeaders + ",Signature=" + sig);
        headers.put("x-amz-date",           amzDate);
        headers.put("x-amz-content-sha256", payloadHash);
        headers.put("Content-Type",         contentType);
        return headers;
    }

    /**
     * Signs headers for PUT /{key}?partNumber={n}&uploadId={id} — Upload Part.
     * ctx keys: accessKey, secretKey, region, bucket, objectKey, partNumber,
     *           uploadId, contentLength (optional)
     */
    public static Map<String, String> signMultipartUploadPart(Map<String, Object> ctx) {
        String accessKey     = str(ctx, "accessKey");
        String secretKey     = str(ctx, "secretKey");
        String region        = str(ctx, "region");
        String bucket        = str(ctx, "bucket");
        String objectKey     = str(ctx, "objectKey");
        String partNumber    = str(ctx, "partNumber");
        String uploadId      = str(ctx, "uploadId");
        String contentLenStr = str(ctx, "contentLength");

        AwsBasicCredentials creds          = AwsBasicCredentials.create(accessKey, secretKey);
        String              canonicalRegion = Region.of(region).id();
        String              encodedKey     = encodeObjectKey(objectKey);
        String              host           = bucket + ".s3." + canonicalRegion + ".amazonaws.com";

        ZonedDateTime now       = ZonedDateTime.now(ZoneOffset.UTC);
        String        amzDate   = now.format(DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'"));
        String        dateStamp = now.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String        credScope = dateStamp + "/" + canonicalRegion + "/s3/aws4_request";

        byte[] signingKey = AWSS3V4Signer.buildSigningKey(
                creds.secretAccessKey(), dateStamp, canonicalRegion, "s3");

        // partNumber < uploadId alphabetically — correct canonical query string order
        String payloadHash    = "UNSIGNED-PAYLOAD";
        String canonicalQuery = "partNumber=" + partNumber +
                                "&uploadId=" + encodeQueryValue(uploadId);
        String signedHeaders  = "host;x-amz-content-sha256;x-amz-date";
        String canonicalRequest =
            "PUT\n" + "/" + encodedKey + "\n" + canonicalQuery + "\n" +
            "host:" + host + "\n" +
            "x-amz-content-sha256:" + payloadHash + "\n" +
            "x-amz-date:" + amzDate + "\n\n" +
            signedHeaders + "\n" + payloadHash;

        String sig = AWSS3V4Signer.hmacHex(signingKey,
            "AWS4-HMAC-SHA256\n" + amzDate + "\n" + credScope + "\n" +
            AWSS3V4Signer.sha256Hex(canonicalRequest));

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization",
            "AWS4-HMAC-SHA256 Credential=" + creds.accessKeyId() + "/" + credScope +
            ",SignedHeaders=" + signedHeaders + ",Signature=" + sig);
        headers.put("x-amz-date",           amzDate);
        headers.put("x-amz-content-sha256", payloadHash);
        // Content-Length not in SignedHeaders — Mule may adjust it when streaming
        if (!nullOrEmpty(contentLenStr)) {
            headers.put("Content-Length", contentLenStr);
        }
        return headers;
    }

    /**
     * Signs headers for POST /{key}?uploadId={id} — Complete Multipart Upload.
     * Uses UNSIGNED-PAYLOAD (same as all other multipart operations) — valid over
     * HTTPS; body integrity is covered by TLS.  bodyHash / bodyLength are no longer
     * required, only the standard multipart ctx keys are used.
     * ctx keys: accessKey, secretKey, region, bucket, objectKey, uploadId
     */
    public static Map<String, String> signMultipartComplete(Map<String, Object> ctx) {
        String accessKey = str(ctx, "accessKey");
        String secretKey = str(ctx, "secretKey");
        String region    = str(ctx, "region");
        String bucket    = str(ctx, "bucket");
        String objectKey = str(ctx, "objectKey");
        String uploadId  = str(ctx, "uploadId");

        AwsBasicCredentials creds          = AwsBasicCredentials.create(accessKey, secretKey);
        String              canonicalRegion = Region.of(region).id();
        String              encodedKey     = encodeObjectKey(objectKey);
        String              host           = bucket + ".s3." + canonicalRegion + ".amazonaws.com";

        ZonedDateTime now       = ZonedDateTime.now(ZoneOffset.UTC);
        String        amzDate   = now.format(DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'"));
        String        dateStamp = now.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String        credScope = dateStamp + "/" + canonicalRegion + "/s3/aws4_request";

        byte[] signingKey = AWSS3V4Signer.buildSigningKey(
                creds.secretAccessKey(), dateStamp, canonicalRegion, "s3");

        String payloadHash    = "UNSIGNED-PAYLOAD";
        String canonicalQuery = "uploadId=" + encodeQueryValue(uploadId);
        String signedHeaders  = "content-type;host;x-amz-content-sha256;x-amz-date";
        String canonicalRequest =
            "POST\n" + "/" + encodedKey + "\n" + canonicalQuery + "\n" +
            "content-type:application/xml\n" +
            "host:" + host + "\n" +
            "x-amz-content-sha256:" + payloadHash + "\n" +
            "x-amz-date:" + amzDate + "\n\n" +
            signedHeaders + "\n" + payloadHash;

        String sig = AWSS3V4Signer.hmacHex(signingKey,
            "AWS4-HMAC-SHA256\n" + amzDate + "\n" + credScope + "\n" +
            AWSS3V4Signer.sha256Hex(canonicalRequest));

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization",
            "AWS4-HMAC-SHA256 Credential=" + creds.accessKeyId() + "/" + credScope +
            ",SignedHeaders=" + signedHeaders + ",Signature=" + sig);
        headers.put("x-amz-date",           amzDate);
        headers.put("x-amz-content-sha256", payloadHash);
        headers.put("Content-Type",         "application/xml");
        return headers;
    }

    /**
     * Signs headers for DELETE /{key}?uploadId={id} — Abort Multipart Upload.
     * ctx keys: accessKey, secretKey, region, bucket, objectKey, uploadId
     */
    public static Map<String, String> signMultipartAbort(Map<String, Object> ctx) {
        String accessKey = str(ctx, "accessKey");
        String secretKey = str(ctx, "secretKey");
        String region    = str(ctx, "region");
        String bucket    = str(ctx, "bucket");
        String objectKey = str(ctx, "objectKey");
        String uploadId  = str(ctx, "uploadId");

        AwsBasicCredentials creds          = AwsBasicCredentials.create(accessKey, secretKey);
        String              canonicalRegion = Region.of(region).id();
        String              encodedKey     = encodeObjectKey(objectKey);
        String              host           = bucket + ".s3." + canonicalRegion + ".amazonaws.com";

        ZonedDateTime now       = ZonedDateTime.now(ZoneOffset.UTC);
        String        amzDate   = now.format(DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'"));
        String        dateStamp = now.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String        credScope = dateStamp + "/" + canonicalRegion + "/s3/aws4_request";

        byte[] signingKey = AWSS3V4Signer.buildSigningKey(
                creds.secretAccessKey(), dateStamp, canonicalRegion, "s3");

        String payloadHash    = "UNSIGNED-PAYLOAD";
        String canonicalQuery = "uploadId=" + encodeQueryValue(uploadId);
        String signedHeaders  = "host;x-amz-content-sha256;x-amz-date";
        String canonicalRequest =
            "DELETE\n" + "/" + encodedKey + "\n" + canonicalQuery + "\n" +
            "host:" + host + "\n" +
            "x-amz-content-sha256:" + payloadHash + "\n" +
            "x-amz-date:" + amzDate + "\n\n" +
            signedHeaders + "\n" + payloadHash;

        String sig = AWSS3V4Signer.hmacHex(signingKey,
            "AWS4-HMAC-SHA256\n" + amzDate + "\n" + credScope + "\n" +
            AWSS3V4Signer.sha256Hex(canonicalRequest));

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization",
            "AWS4-HMAC-SHA256 Credential=" + creds.accessKeyId() + "/" + credScope +
            ",SignedHeaders=" + signedHeaders + ",Signature=" + sig);
        headers.put("x-amz-date",           amzDate);
        headers.put("x-amz-content-sha256", payloadHash);
        return headers;
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

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

    /** URL-encodes a single query-string value for the SigV4 canonical query string. */
    private static String encodeQueryValue(String value) {
        try {
            return java.net.URLEncoder.encode(
                    value, java.nio.charset.StandardCharsets.UTF_8.name())
                    .replace("+", "%20");
        } catch (java.io.UnsupportedEncodingException e) {
            throw new AssertionError("UTF-8 is always supported", e);
        }
    }

    private static String str(Map<String, Object> ctx, String key) {
        Object v = ctx.get(key);
        return v == null ? "" : v.toString();
    }

    private static boolean nullOrEmpty(String s) {
        return s == null || s.isEmpty();
    }

    // =========================================================================
    // readPart — returns a lazy stream for a single multipart part.
    //
    // Why this is needed for multipart:
    //   The Mule CursorStreamProvider always opens a cursor from the BEGINNING
    //   of the stream.  If we pass the raw provider as the body for every part,
    //   every iteration sends the ENTIRE file (all 197 MB) rather than its 25 MB
    //   slice — both corrupting the data and exhausting the heap.
    //   readPart returns a LazySkippingInputStream: on first read() (inside
    //   http:request body transfer) it opens a fresh cursor, skips to the
    //   correct byte offset, then delivers exactly partSize bytes.
    //
    // Called from Mule via java:invoke-static.
    // =========================================================================

    /**
     * Returns a lazy stream for a single multipart part.
     *
     * <p><b>Why lazy:</b> Mule 4's {@code ManagedCursorStreamProvider.openCursor()} must be
     * called within the lifecycle context of the component that consumes the cursor
     * (i.e. inside {@code http:request}'s body transfer). Calling it eagerly during
     * {@code java:invoke-static} fails with "Failed to open cursor". The same pattern is
     * used by {@link LazyCursorInputStream} for the simple-upload path.
     *
     * <p>On the first {@code read()} call (which happens inside {@code http:request}):
     * <ol>
     *   <li>Opens a fresh cursor via {@code openCursor()} reflection</li>
     *   <li>Skips {@code offset} bytes using a read-and-discard loop</li>
     *   <li>Reads up to {@code length} bytes, then signals EOF</li>
     * </ol>
     *
     * @param ctx Map with keys:
     *              provider – CursorStreamProvider / InputStream / byte[]
     *              offset   – start byte offset (String) = (partNumber-1) * partSize
     *              length   – number of bytes for this part (String)
     * @return InputStream limited to exactly {@code length} bytes starting at {@code offset}
     */
    public static InputStream readPart(Map<String, Object> ctx) {
        Object provider = ctx.get("provider");
        long   offset   = Long.parseLong(str(ctx, "offset"));
        long   length   = Long.parseLong(str(ctx, "length"));
        if (provider == null) {
            throw new IllegalArgumentException("ctx['provider'] must not be null");
        }

        // ── Fast path: byte[] (set via "payload as Binary" in Mule flow) ────────
        // ByteArrayInputStream(buf, offset, len) is a zero-copy view into the
        // original array — no extra heap beyond the one copy already stored in
        // vars.fileStream.  Mule's http:request sees a known-size InputStream
        // (available() == len) and sends it with Content-Length reliably.
        // This sidesteps all ManagedCursorStreamProvider lifecycle issues.
        if (provider instanceof byte[]) {
            byte[] bytes   = (byte[]) provider;
            int    iOffset = (int) Math.min(offset, (long) bytes.length);
            int    iLength = (int) Math.min(length, (long) bytes.length - iOffset);
            return new java.io.ByteArrayInputStream(bytes, iOffset, iLength);
        }

        // ── Fallback: CursorStreamProvider / InputStream ─────────────────────────
        // LazySkippingInputStream defers openCursor() to the first read() call
        // (inside http:request body transfer) as ManagedCursorStreamProvider
        // requires cursor opens to happen within the consuming component's context.
        return new LazySkippingInputStream(provider, offset, length);
    }

    // =========================================================================
    // LazySkippingInputStream — defers openCursor() + skip until first read().
    //
    // openCursor() on Mule's ManagedCursorStreamProvider must be called while
    // the http:request component is actively consuming the body. Deferring to
    // first read() keeps the cursor lifetime aligned with the consumer,
    // matching the behaviour of LazyCursorInputStream used by signRequest().
    // =========================================================================
    private static final class LazySkippingInputStream extends InputStream {

        private final Object provider;   // CursorStreamProvider / InputStream / byte[]
        private final long   offset;     // bytes to skip from the start of the stream
        private final long   limit;      // max bytes to deliver to the caller
        private InputStream  delegate;   // opened lazily on first read()
        private long         remaining;  // bytes still deliverable

        LazySkippingInputStream(Object provider, long offset, long limit) {
            this.provider  = provider;
            this.offset    = offset;
            this.limit     = limit;
            this.remaining = limit;
        }

        /** Opens cursor + skips to offset on first read(). */
        private InputStream delegate() throws java.io.IOException {
            if (delegate != null) return delegate;

            // ── Open base stream ─────────────────────────────────────────────
            InputStream base;
            if (provider instanceof byte[]) {
                base = new java.io.ByteArrayInputStream((byte[]) provider);
            } else if (provider instanceof InputStream) {
                base = (InputStream) provider;
            } else {
                // Mule 4 CursorStreamProvider (ManagedCursorStreamProvider etc.)
                // openCursor() always rewinds to byte 0 of the original stream.
                try {
                    java.lang.reflect.Method m = provider.getClass().getMethod("openCursor");
                    base = (InputStream) m.invoke(provider);
                } catch (Exception e) {
                    throw new java.io.IOException(
                            "Failed to open cursor from " + provider.getClass().getName()
                            + ": " + e.getMessage(), e);
                }
            }

            // ── Skip to offset ───────────────────────────────────────────────
            // Use read-and-discard; InputStream.skip() is not guaranteed to skip
            // the full requested amount on every call.
            if (offset > 0) {
                byte[] skipBuf    = new byte[65_536];
                long   toSkip     = offset;
                while (toSkip > 0) {
                    int n = base.read(skipBuf, 0, (int) Math.min(toSkip, skipBuf.length));
                    if (n < 0) {
                        throw new java.io.EOFException(
                                "Stream ended at byte " + (offset - toSkip)
                                + " before reaching offset " + offset);
                    }
                    toSkip -= n;
                }
            }

            delegate = base;
            return delegate;
        }

        @Override
        public int read() throws java.io.IOException {
            if (remaining <= 0) return -1;
            int b = delegate().read();
            if (b >= 0) remaining--;
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws java.io.IOException {
            if (remaining <= 0) return -1;
            int toRead = (int) Math.min(len, remaining);
            int n      = delegate().read(b, off, toRead);
            if (n > 0) remaining -= n;
            return n;
        }

        @Override
        public void close() throws java.io.IOException {
            if (delegate != null) delegate.close();
        }
    }

    // =========================================================================
    // LazyCursorInputStream — defers CursorStreamProvider.openCursor() until
    // the first read() call.
    //
    // Why lazy: Mule 4 tracks every cursor opened within a component's execution
    // and closes it when that component finishes. If we called openCursor() inside
    // the Groovy scripting component, the cursor would be closed before the
    // http:request connector begins reading the body — causing "Stream is closed".
    //
    // By deferring openCursor() to the first read() (which happens inside the
    // http:request component), the cursor's lifetime aligns with the component
    // that actually consumes it.
    //
    // CursorStreamProvider is a Mule API type; we invoke openCursor() via
    // reflection to avoid a compile-time mule-api dependency.
    // =========================================================================
    private static final class LazyCursorInputStream extends InputStream {

        private final Object    provider;  // CursorStreamProvider instance
        private       InputStream cursor;  // opened on first read

        LazyCursorInputStream(Object provider) {
            this.provider = provider;
        }

        private InputStream cursor() throws java.io.IOException {
            if (cursor == null) {
                try {
                    java.lang.reflect.Method m =
                            provider.getClass().getMethod("openCursor");
                    cursor = (InputStream) m.invoke(provider);
                } catch (Exception e) {
                    throw new java.io.IOException(
                            "Failed to open cursor from "
                            + provider.getClass().getName(), e);
                }
            }
            return cursor;
        }

        @Override public int read() throws java.io.IOException {
            return cursor().read();
        }

        @Override public int read(byte[] b, int off, int len) throws java.io.IOException {
            return cursor().read(b, off, len);
        }

        @Override public int available() throws java.io.IOException {
            return cursor == null ? 0 : cursor.available();
        }

        @Override public void close() throws java.io.IOException {
            if (cursor != null) cursor.close();
        }
    }
}
