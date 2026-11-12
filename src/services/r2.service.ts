import {
  S3Client,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
  CreateMultipartUploadCommand,
  CompleteMultipartUploadCommand,
  AbortMultipartUploadCommand,
  UploadPartCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { env } from "../config/env";

const r2Client = new S3Client({
  region: "auto",
  endpoint: env.R2_ENDPOINT,
  credentials: {
    accessKeyId: env.R2_ACCESS_KEY_ID,
    secretAccessKey: env.R2_SECRET_ACCESS_KEY,
  },
});

const BUCKET_NAME = env.R2_BUCKET_NAME;

// Upload URLs need a long-enough window for slow connections to finish a
// multi-GiB upload before the signature expires (1 MB/s on a 10 GiB
// upload ≈ 2.8 h). PUT URLs are write-only and bound to
// (key, content-length).
export const UPLOAD_URL_EXPIRY = 4 * 60 * 60;
// A streamed download issues ranged GETs against one URL for the whole
// file, so the URL has to outlive a large download on a slow line.
const DOWNLOAD_URL_EXPIRY = 4 * 60 * 60;

export interface PresignedDownloadUrl {
  url: string;
  expiresAt: Date;
}

/**
 * Look up an object's size in R2. Returns null when the object does not
 * exist (404 from HeadObject) so callers can distinguish "absent" from
 * "present but mismatched size".
 */
export async function headObject(key: string): Promise<{ size: number } | null> {
  try {
    const result = await r2Client.send(
      new HeadObjectCommand({ Bucket: BUCKET_NAME, Key: key }),
    );
    return { size: result.ContentLength ?? 0 };
  } catch (err) {
    const status = (err as { $metadata?: { httpStatusCode?: number } })
      .$metadata?.httpStatusCode;
    const name = (err as { name?: string }).name;
    if (status === 404 || name === "NotFound" || name === "NoSuchKey") {
      return null;
    }
    throw err;
  }
}

/**
 * Generate a presigned URL for downloading a file from R2. `notAfter`
 * is the transfer's expiry: the URL never outlives the transfer.
 */
export async function getPresignedDownloadUrl(
  key: string,
  notAfter: Date,
): Promise<PresignedDownloadUrl> {
  const command = new GetObjectCommand({
    Bucket: BUCKET_NAME,
    Key: key,
  });

  const untilTransferExpires = Math.floor((notAfter.getTime() - Date.now()) / 1000);
  const expiresIn = Math.max(1, Math.min(DOWNLOAD_URL_EXPIRY, untilTransferExpires));
  const url = await getSignedUrl(r2Client, command, { expiresIn });

  const expiresAt = new Date(Date.now() + expiresIn * 1000);

  return { url, expiresAt };
}

/**
 * Delete a file from R2
 */
export async function deleteFromR2(key: string): Promise<void> {
  const command = new DeleteObjectCommand({
    Bucket: BUCKET_NAME,
    Key: key,
  });

  await r2Client.send(command);
}

// ─── Multipart upload ────────────────────────────────────────────────────────
//
// Standard S3 multipart: init → upload parts → complete (or abort).
// Each Part is signed with its own presigned URL so the browser uploads
// directly to R2; the server never proxies the bytes.

// S3 minimum part size is 5 MB except for the final part. 10 MB keeps per-part
// retries cheap and limits how much data is in flight at once (part size ×
// client parallelism), which reduces connection drops on big uploads — while
// staying large enough that throughput on a fast network stays bandwidth-bound
// rather than request-bound.
export const MULTIPART_PART_SIZE = 10 * 1024 * 1024;

export interface PresignedPartUrl {
  partNumber: number;
  url: string;
  contentLength: number;
}

export interface MultipartUploadInit {
  uploadId: string;
  key: string;
  partUrls: PresignedPartUrl[];
}

export interface MultipartCompletePart {
  partNumber: number;
  etag: string;
}

/**
 * Begin a Multipart upload and return all Part URLs in one batch.
 *
 * Each URL is bound to its specific `partNumber` + `contentLength`,
 * so R2 will reject a body whose size doesn't match. The Upload ID
 * ties every subsequent UploadPart / Complete / Abort call back to
 * this Multipart upload.
 */
export async function initMultipartUpload(
  key: string,
  totalBytes: number,
  contentType: string = "application/octet-stream",
): Promise<MultipartUploadInit> {
  const createResult = await r2Client.send(
    new CreateMultipartUploadCommand({
      Bucket: BUCKET_NAME,
      Key: key,
      ContentType: contentType,
    }),
  );
  const uploadId = createResult.UploadId;
  if (!uploadId) {
    throw new Error("R2 CreateMultipartUpload returned no UploadId");
  }

  const partCount = Math.max(1, Math.ceil(totalBytes / MULTIPART_PART_SIZE));
  const partUrls: PresignedPartUrl[] = [];

  for (let i = 0; i < partCount; i++) {
    // S3 part numbers are 1-indexed.
    const partNumber = i + 1;
    const offset = i * MULTIPART_PART_SIZE;
    const isLast = i === partCount - 1;
    const contentLength = isLast ? totalBytes - offset : MULTIPART_PART_SIZE;

    const command = new UploadPartCommand({
      Bucket: BUCKET_NAME,
      Key: key,
      UploadId: uploadId,
      PartNumber: partNumber,
      ContentLength: contentLength,
    });

    const url = await getSignedUrl(r2Client, command, {
      expiresIn: UPLOAD_URL_EXPIRY,
      unhoistableHeaders: new Set(["content-length"]),
    });

    partUrls.push({ partNumber, url, contentLength });
  }

  return { uploadId, key, partUrls };
}

/**
 * Stitch the uploaded Parts into a single R2 object. `parts` must list
 * every Part by number with its etag. Sorted defensively before send
 * because R2 requires ascending order.
 */
export async function completeMultipartUpload(
  key: string,
  uploadId: string,
  parts: MultipartCompletePart[],
): Promise<void> {
  const sorted = [...parts].sort((a, b) => a.partNumber - b.partNumber);
  await r2Client.send(
    new CompleteMultipartUploadCommand({
      Bucket: BUCKET_NAME,
      Key: key,
      UploadId: uploadId,
      MultipartUpload: {
        Parts: sorted.map((p) => ({ PartNumber: p.partNumber, ETag: p.etag })),
      },
    }),
  );
}

/**
 * Discard a Multipart upload at R2. Idempotent — duplicate aborts and
 * aborts of already-completed uploads are swallowed.
 */
export async function abortMultipartUpload(
  key: string,
  uploadId: string,
): Promise<void> {
  try {
    await r2Client.send(
      new AbortMultipartUploadCommand({
        Bucket: BUCKET_NAME,
        Key: key,
        UploadId: uploadId,
      }),
    );
  } catch (err) {
    const status = (err as { $metadata?: { httpStatusCode?: number } })
      .$metadata?.httpStatusCode;
    const name = (err as { name?: string }).name;
    if (status === 404 || name === "NoSuchUpload") return;
    throw err;
  }
}
