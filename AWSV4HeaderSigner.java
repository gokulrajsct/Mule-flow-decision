package com.mycompany.s3;


import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.auth.signer.Aws4Signer;
import software.amazon.awssdk.auth.signer.params.Aws4SignerParams;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.regions.Region;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * AWS Signature V4 Header Generator for MuleSoft HTTP Requester
 * 
 * This class ONLY generates signed headers - the actual HTTP call
 * is handled by MuleSoft's HTTP Requester connector with streaming enabled.
 * 
 * Usage in DataWeave:
 *   %dw 2.0
 *   import java!com::mulesoft::aws::AWSV4HeaderSigner
 *   var signer = AWSV4HeaderSigner::new(accessKey, secretKey, region, endpoint)
 *   var headers = signer.signPutObject(bucket, key, contentType, contentLength)
 */
public class AWSV4HeaderSigner {

    private static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    
    private final AwsBasicCredentials credentials;
    private final Region region;
    private final String endpoint;
    private final Aws4Signer signer;
    
    /**
     * Create a new signer instance
     * 
     * @param accessKey AWS/Cloudflare R2 access key
     * @param secretKey AWS/Cloudflare R2 secret key
     * @param regionStr Region (use "auto" for Cloudflare R2)
     * @param endpoint  Endpoint URL (e.g., https://ACCOUNT_ID.r2.cloudflarestorage.com)
     */
    public AWSV4HeaderSigner(String accessKey, String secretKey, String regionStr, String endpoint) {
        this.credentials = AwsBasicCredentials.create(accessKey, secretKey);
        // Cloudflare R2 uses "auto" but SDK needs a valid region - use us-east-1 as fallback
        this.region = "auto".equalsIgnoreCase(regionStr) ? Region.US_EAST_1 : Region.of(regionStr);
        this.endpoint = endpoint;
        this.signer = Aws4Signer.create();
    }
    
    /**
     * Generate signed headers for PUT object (single upload)
     * Use UNSIGNED-PAYLOAD to enable streaming without buffering
     * 
     * @param bucketName    S3/R2 bucket name
     * @param objectKey     Object key (path in bucket)
     * @param contentType   MIME type of the file
     * @param contentLength File size in bytes
     * @return Map of headers to pass to HTTP Requester
     */
    public Map<String, String> signPutObject(
            String bucketName,
            String objectKey,
            String contentType,
            long contentLength) {
        
        String path = "/" + bucketName + "/" + objectKey;
        URI uri = URI.create(endpoint + path);
        
        // Content-Length is excluded from SignedHeaders intentionally.
        // Mule's HTTP Requester can modify Content-Length after signing when
        // streaming mode is active, which causes SignatureDoesNotMatch.
        // Content-Length is passed as a separate unsigned header in the Mule flow.
        SdkHttpFullRequest request = SdkHttpFullRequest.builder()
            .method(SdkHttpMethod.PUT)
            .uri(uri)
            .putHeader("Host", uri.getHost())
            .putHeader("Content-Type", contentType)
            .putHeader("x-amz-content-sha256", UNSIGNED_PAYLOAD)
            .build();

        Aws4SignerParams signerParams = Aws4SignerParams.builder()
            .signingName("s3")
            .signingRegion(region)
            .awsCredentials(credentials)
            .build();

        SdkHttpFullRequest signedRequest = signer.sign(request, signerParams);

        return extractHeaders(signedRequest);
    }

    /**
     * Generate signed headers for initiating multipart upload
     */
    public Map<String, String> signInitiateMultipart(
            String bucketName,
            String objectKey,
            String contentType) {
        
        String path = "/" + bucketName + "/" + objectKey;
        URI uri = URI.create(endpoint + path + "?uploads");
        
        SdkHttpFullRequest request = SdkHttpFullRequest.builder()
            .method(SdkHttpMethod.POST)
            .uri(uri)
            .putHeader("Host", uri.getHost())
            .putHeader("Content-Type", contentType)
            .putHeader("x-amz-content-sha256", UNSIGNED_PAYLOAD)
            .build();
        
        Aws4SignerParams signerParams = Aws4SignerParams.builder()
            .signingName("s3")
            .signingRegion(region)
            .awsCredentials(credentials)
            .build();
        
        SdkHttpFullRequest signedRequest = signer.sign(request, signerParams);
        
        return extractHeaders(signedRequest);
    }
    
    /**
     * Generate signed headers for uploading a part
     */
    public Map<String, String> signUploadPart(
            String bucketName,
            String objectKey,
            String uploadId,
            int partNumber,
            long partSize) {
        
        String path = "/" + bucketName + "/" + objectKey;
        String query = "partNumber=" + partNumber + "&uploadId=" + uploadId;
        URI uri = URI.create(endpoint + path + "?" + query);
        
        // Content-Length excluded from SignedHeaders — same reason as signPutObject.
        SdkHttpFullRequest request = SdkHttpFullRequest.builder()
            .method(SdkHttpMethod.PUT)
            .uri(uri)
            .putHeader("Host", uri.getHost())
            .putHeader("x-amz-content-sha256", UNSIGNED_PAYLOAD)
            .build();

        Aws4SignerParams signerParams = Aws4SignerParams.builder()
            .signingName("s3")
            .signingRegion(region)
            .awsCredentials(credentials)
            .build();

        SdkHttpFullRequest signedRequest = signer.sign(request, signerParams);

        return extractHeaders(signedRequest);
    }

    /**
     * Generate signed headers for completing multipart upload
     * Note: For complete, the body hash must be computed - pass it in
     */
    public Map<String, String> signCompleteMultipart(
            String bucketName,
            String objectKey,
            String uploadId,
            String bodyHash,
            int bodyLength) {
        
        String path = "/" + bucketName + "/" + objectKey;
        URI uri = URI.create(endpoint + path + "?uploadId=" + uploadId);
        
        SdkHttpFullRequest request = SdkHttpFullRequest.builder()
            .method(SdkHttpMethod.POST)
            .uri(uri)
            .putHeader("Host", uri.getHost())
            .putHeader("Content-Type", "application/xml")
            .putHeader("Content-Length", String.valueOf(bodyLength))
            .putHeader("x-amz-content-sha256", bodyHash)
            .build();
        
        Aws4SignerParams signerParams = Aws4SignerParams.builder()
            .signingName("s3")
            .signingRegion(region)
            .awsCredentials(credentials)
            .build();
        
        SdkHttpFullRequest signedRequest = signer.sign(request, signerParams);
        
        return extractHeaders(signedRequest);
    }
    
    /**
     * Generate signed headers for aborting multipart upload
     */
    public Map<String, String> signAbortMultipart(
            String bucketName,
            String objectKey,
            String uploadId) {
        
        String path = "/" + bucketName + "/" + objectKey;
        URI uri = URI.create(endpoint + path + "?uploadId=" + uploadId);
        
        SdkHttpFullRequest request = SdkHttpFullRequest.builder()
            .method(SdkHttpMethod.DELETE)
            .uri(uri)
            .putHeader("Host", uri.getHost())
            .putHeader("x-amz-content-sha256", UNSIGNED_PAYLOAD)
            .build();
        
        Aws4SignerParams signerParams = Aws4SignerParams.builder()
            .signingName("s3")
            .signingRegion(region)
            .awsCredentials(credentials)
            .build();
        
        SdkHttpFullRequest signedRequest = signer.sign(request, signerParams);
        
        return extractHeaders(signedRequest);
    }
    
    /**
     * Utility: Compute SHA-256 hash for complete multipart body
     */
    public static String sha256Hex(String data) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 computation failed", e);
        }
    }
    
    /**
     * Get the full URL for a PUT request (for HTTP Requester)
     */
    public String getPutUrl(String bucketName, String objectKey) {
        return endpoint + "/" + bucketName + "/" + objectKey;
    }
    
    /**
     * Get the URL for initiating multipart upload
     */
    public String getInitiateMultipartUrl(String bucketName, String objectKey) {
        return endpoint + "/" + bucketName + "/" + objectKey + "?uploads";
    }
    
    /**
     * Get the URL for uploading a part
     */
    public String getUploadPartUrl(String bucketName, String objectKey, String uploadId, int partNumber) {
        return endpoint + "/" + bucketName + "/" + objectKey 
            + "?partNumber=" + partNumber + "&uploadId=" + uploadId;
    }
    
    /**
     * Get the URL for completing multipart upload
     */
    public String getCompleteMultipartUrl(String bucketName, String objectKey, String uploadId) {
        return endpoint + "/" + bucketName + "/" + objectKey + "?uploadId=" + uploadId;
    }
    
    // ============== Private Helpers ==============
    
    private Map<String, String> extractHeaders(SdkHttpFullRequest signedRequest) {
        Map<String, String> headers = new HashMap<>();
        signedRequest.headers().forEach((key, values) -> {
            if (!values.isEmpty() && !key.equalsIgnoreCase("Host")) {
                headers.put(key, values.get(0));
            }
        });
        return headers;
    }
}