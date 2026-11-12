// Password-gated /file/:id/url. See docs/audit/25-external-audit-findings.md §A.4.
//
// A password-protected transfer must require the short-lived HMAC token
// issued by /transfer/:id/verify on every subsequent /file/:id/url call.
// Tokens are transfer-scoped: a token for transfer A cannot claim a file
// belonging to transfer B. Existence-oracle policy from doc 20 §4 still
// dominates — for expired/deleted/non-completed transfers we 404 instead of
// 401, so an attacker can't probe which transfers were ever password
// protected.

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { createApp } from "../../src/app";
import {
  createTransfer,
  createFile,
  completeTransfer,
  markTransferAsDeleted,
} from "../../src/services/file.service";
import { issueDownloadToken } from "../../src/auth/downloadTokens";
import { db } from "../../src/db";
import { transfers } from "../../src/db/schema";
import { eq } from "drizzle-orm";
import { ensureMigrations, resetDb } from "../helpers/db";

const APP_URL = process.env.APP_URL!;
const JSON_HEADERS = { Origin: APP_URL, "Content-Type": "application/json" };

let app: ReturnType<typeof createApp>;

beforeAll(async () => {
  await ensureMigrations();
  app = createApp();
});

beforeEach(async () => {
  await resetDb();
});

afterAll(async () => {
  await resetDb();
});

async function seedTransfer(opts: { password?: string; expiresInHours?: number } = {}) {
  const transfer = await createTransfer(
    opts.expiresInHours ?? 1,
    opts.password,
    undefined,
  );
  const file = await createFile({
    transferId: transfer.id,
    encryptedName: "x".repeat(32),
    encryptedNameIv: "y".repeat(24),
    fileIv: "z".repeat(24),
    size: 1024,
    mimeType: "application/octet-stream",
  });
  await completeTransfer(transfer.id);
  return { transfer, file };
}

function fileUrlRequest(fileId: string, opts: { token?: string; ip?: string } = {}) {
  const headers: Record<string, string> = {
    Origin: APP_URL,
    "cf-connecting-ip": opts.ip ?? `203.0.113.${Math.floor(Math.random() * 200) + 1}`,
  };
  if (opts.token) headers["x-transfer-token"] = opts.token;
  return new Request(`${APP_URL}/api/download/file/${fileId}/url`, { headers });
}

// ─── 1. Password-protected transfer requires a token ───────────────────────

describe("GET /api/download/file/:id/url — password gate", () => {
  it("returns 401 when the transfer has a password and no token is presented", async () => {
    const { file } = await seedTransfer({ password: "correct-horse-battery-staple" });
    const res = await app.handle(fileUrlRequest(file.id));
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain("Password verification");
  });

  it("returns 401 when the token is structurally invalid", async () => {
    const { file } = await seedTransfer({ password: "correct-horse-battery-staple" });
    const res = await app.handle(fileUrlRequest(file.id, { token: "not-a-real-token" }));
    expect(res.status).toBe(401);
  });

  it("returns 401 when the token was issued for a different transfer", async () => {
    const { file } = await seedTransfer({ password: "correct-horse-battery-staple" });
    const other = await createTransfer(1);
    const wrongToken = await issueDownloadToken(other.id);
    const res = await app.handle(fileUrlRequest(file.id, { token: wrongToken.token }));
    expect(res.status).toBe(401);
  });

  it("returns 401 when the token signature is tampered with", async () => {
    const { transfer, file } = await seedTransfer({ password: "correct-horse-battery-staple" });
    const valid = await issueDownloadToken(transfer.id);
    // Flip the last char of the signature.
    const tampered = valid.token.slice(0, -1) + (valid.token.endsWith("A") ? "B" : "A");
    const res = await app.handle(fileUrlRequest(file.id, { token: tampered }));
    expect(res.status).toBe(401);
  });

  it("returns 200 with a valid token for the right transfer", async () => {
    const { transfer, file } = await seedTransfer({ password: "correct-horse-battery-staple" });
    const valid = await issueDownloadToken(transfer.id);
    const res = await app.handle(fileUrlRequest(file.id, { token: valid.token }));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { downloadUrl: string; size: number };
    expect(body.downloadUrl).toBeTruthy();
    expect(body.size).toBe(1024);
  });
});

// ─── 2. Non-protected transfers must still work without a token ────────────

describe("GET /api/download/file/:id/url — no password configured", () => {
  it("returns 200 with no X-Transfer-Token header when the transfer is unprotected", async () => {
    const { file } = await seedTransfer();
    const res = await app.handle(fileUrlRequest(file.id));
    expect(res.status).toBe(200);
  });
});

// ─── 3. Existence-oracle preserved on dead transfers ───────────────────────

describe("GET /api/download/file/:id/url — dead transfers always 404", () => {
  it("returns 404 (not 401) when the transfer is soft-deleted", async () => {
    const { transfer, file } = await seedTransfer({ password: "correct-horse-battery-staple" });
    await markTransferAsDeleted(transfer.id);
    const res = await app.handle(fileUrlRequest(file.id));
    expect(res.status).toBe(404);
  });

  it("returns 404 (not 401) when the transfer has expired", async () => {
    const { transfer, file } = await seedTransfer({ password: "correct-horse-battery-staple" });
    await db
      .update(transfers)
      .set({ expiresAt: new Date(Date.now() - 60_000) })
      .where(eq(transfers.id, transfer.id));
    const res = await app.handle(fileUrlRequest(file.id));
    expect(res.status).toBe(404);
  });
});

// ─── 4. /transfer/:id/verify returns a usable token ────────────────────────

describe("POST /api/download/transfer/:id/verify — issues access token", () => {
  it("returns accessToken alongside files on successful password verification", async () => {
    const { transfer, file } = await seedTransfer({ password: "correct-horse-battery-staple" });
    const res = await app.handle(
      new Request(`${APP_URL}/api/download/transfer/${transfer.id}/verify`, {
        method: "POST",
        headers: JSON_HEADERS,
        body: JSON.stringify({ password: "correct-horse-battery-staple" }),
      }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      accessToken: string;
      accessTokenExpiresAt: string;
      files: unknown[];
    };
    expect(body.accessToken).toBeTruthy();
    expect(body.files).toHaveLength(1);

    // The returned token must unlock the file URL.
    const urlRes = await app.handle(fileUrlRequest(file.id, { token: body.accessToken }));
    expect(urlRes.status).toBe(200);
  });
});

// ─── Password verifier with a client-side salt ─────────────────────────────

describe("password salt round trip", () => {
  const SALT = Buffer.alloc(16, 7).toString("base64url");
  const post = (path: string, body: object) =>
    app.handle(
      new Request(`${APP_URL}${path}`, {
        method: "POST",
        headers: {
          Origin: APP_URL,
          "Content-Type": "application/json",
          "cf-connecting-ip": `203.0.113.${Math.floor(Math.random() * 200) + 1}`,
        },
        body: JSON.stringify(body),
      }),
    );

  it("stores the salt and returns it before the password is verified", async () => {
    const created = await post("/api/upload/create-transfer", {
      expiresInHours: 1,
      password: "derived-verifier-not-the-password",
      passwordSalt: SALT,
    });
    expect(created.status).toBe(200);
    const { transferId } = (await created.json()) as { transferId: string };
    await createFile({
      transferId,
      encryptedName: "x".repeat(32),
      encryptedNameIv: "y".repeat(24),
      fileIv: "z".repeat(24),
      size: 1024,
      mimeType: "application/octet-stream",
    });
    await completeTransfer(transferId);

    const meta = await app.handle(
      new Request(`${APP_URL}/api/download/transfer/${transferId}`, {
        headers: { Origin: APP_URL, "cf-connecting-ip": "203.0.113.77" },
      }),
    );
    const body = (await meta.json()) as { passwordRequired: boolean; passwordSalt: string | null };
    expect(body.passwordRequired).toBe(true);
    expect(body.passwordSalt).toBe(SALT);

    const ok = await post(`/api/download/transfer/${transferId}/verify`, {
      password: "derived-verifier-not-the-password",
    });
    expect(ok.status).toBe(200);
  });

  it("returns a null salt for a transfer created without one", async () => {
    const { transfer } = await seedTransfer({ password: "legacy-password" });
    const meta = await app.handle(
      new Request(`${APP_URL}/api/download/transfer/${transfer.id}`, {
        headers: { Origin: APP_URL, "cf-connecting-ip": "203.0.113.78" },
      }),
    );
    const body = (await meta.json()) as { passwordSalt: string | null };
    expect(body.passwordSalt).toBeNull();
  });

  it("rejects a malformed salt or a salt without a password", async () => {
    const short = await post("/api/upload/create-transfer", {
      expiresInHours: 1,
      password: "derived-verifier-not-the-password",
      passwordSalt: "AAAA",
    });
    expect(short.status).toBe(400);

    const alone = await post("/api/upload/create-transfer", {
      expiresInHours: 1,
      passwordSalt: SALT,
    });
    expect(alone.status).toBe(400);
  });
});
