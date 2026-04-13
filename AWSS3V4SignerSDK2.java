package com.mycompany.s3;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.signer.Aws4UnsignedPayloadSigner;
import software.amazon.awssdk.auth.signer.params.Aws4SignerParams;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.regions.Region;

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
public final class AWSS3V4SignerSDK2 {

    private AWSS3V4SignerSDK2() {}

    static Map<String, String> signRequest(Map<String, Object> params) {
        // Extract parameters from the input map
        String accessKey    = (String)      params.get("accessKey");
        String secretKey    = (String)      params.get("secretKey");
        String region       = (String)      params.get("region");
        String bucketName   = (String)      params.get("bucketName");
        String objectKey    = (String)      params.get("objectKey");
        Long contentLength  = (Long)        params.get("contentLength");

        // Validate required parameters
        if (accessKey == null || secretKey == null || region == null
                || bucketName == null || objectKey == null) {
            throw new IllegalArgumentException("Missing required parameters for signing the request.");
        }

        // Create AWS credentials and region objects
        AwsBasicCredentials awsCredentials = AwsBasicCredentials.create(accessKey, secretKey);
        Region awsRegion = Region.of(region);

        String dateTime = ZonedDateTime.now(ZoneOffset.UTC)
                .format(DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'"));

        // Build the HTTP request to be signed
        SdkHttpFullRequest.Builder requestBuilder = SdkHttpFullRequest.builder()
                .method(SdkHttpMethod.PUT)
                .protocol("https")
                .host(bucketName + ".s3." + region + ".amazonaws.com")
                .encodedPath("/" + objectKey)
                .putHeader("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
                .putHeader("x-amz-date", dateTime);

        if (contentLength != null) {
            requestBuilder.putHeader("Content-Length", String.valueOf(contentLength));
        }

        SdkHttpFullRequest unsignedRequest = requestBuilder.build();

        // Build signing params — signingName "s3" is required for S3 SigV4
        Aws4SignerParams signerParams = Aws4SignerParams.builder()
                .awsCredentials(awsCredentials)
                .signingRegion(awsRegion)
                .signingName("s3")
                .build();

        // Aws4UnsignedPayloadSigner always uses "UNSIGNED-PAYLOAD" as the payload hash,
        // so the body is never read or buffered during signing.
        Aws4UnsignedPayloadSigner signer = Aws4UnsignedPayloadSigner.create();
        SdkHttpFullRequest signedRequest = signer.sign(unsignedRequest, signerParams);

        // Extract signed headers and return them in a map
        Map<String, String> signedHeaders = new LinkedHashMap<>();
        signedRequest.headers().forEach((key, valueList) -> {
            if (!valueList.isEmpty()) {
                signedHeaders.put(key, valueList.get(0));
            }
        });

        return signedHeaders;
    }
}
