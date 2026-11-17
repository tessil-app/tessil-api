// Forms: portals whose bundle holds questions, counted apart from portals.
// See docs/adr/0016-encrypted-forms.md.

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { eq } from "drizzle-orm";
import { nanoid } from "nanoid";
import { createApp } from "../../src/app";
import { db } from "../../src/db";
import { portals, users } from "../../src/db/schema";
import { buildPortalNotice } from "../../src/services/email.service";
import { ANSWERS_MAX_BYTES, ANSWERS_MIME_TYPE } from "../../src/services/file.service";
import { resetRateLimits } from "../../src/services/ratelimit.service";
import { authedRequest, createAuthedUser } from "../helpers/auth";
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
  await resetRateLimits();
});
afterAll(resetDb);

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const BUNDLE = b64(new Uint8Array(140).fill(3));
const SEALED = b64(new Uint8Array(260).fill(4));
const TOKEN = b64(new Uint8Array(32).fill(6));
const SEALED_KEY = b64(new Uint8Array(114).fill(5));
const FILE_FIELDS = {
  encryptedName: "x".repeat(32),
  encryptedNameIv: "y".repeat(24),
  fileIv: "z".repeat(24),
};

async function account(tier: string) {
  const authed = await createAuthedUser();
  await db.update(users).set({ tier, publicKey: new Uint8Array(65).fill(4) }).where(eq(users.id, authed.user.id));
  return authed;
}

function call(cookie: string | null, method: string, path: string, body?: object) {
  const init: RequestInit = { method, headers: JSON_HEADERS };
  if (body) init.body = JSON.stringify(body);
  const url = `${APP_URL}${path}`;
  return app.handle(cookie ? authedRequest(cookie, url, init) : new Request(url, init));
}

function create(cookie: string, kind?: "portal" | "form") {
  return call(cookie, "POST", "/api/portals", {
    id: nanoid(),
    publicBundle: BUNDLE,
    sealedKeys: SEALED,
    depositToken: TOKEN,
    ...(kind ? { kind } : {}),
  });
}

describe("creating a form", () => {
  it("stores the kind and lists it with the form limit", async () => {
    const { cookie } = await account("pro");
    expect((await create(cookie, "form")).status).toBe(201);
    expect((await create(cookie)).status).toBe(201);

    const list = (await (await call(cookie, "GET", "/api/portals")).json()) as {
      maxPortals: number;
      maxForms: number;
      portals: { kind: string }[];
    };
    expect(list.maxPortals).toBe(3);
    expect(list.maxForms).toBe(3);
    expect(list.portals.map((p) => p.kind).sort()).toEqual(["form", "portal"]);
  });

  it("is refused on the free plan with its own code", async () => {
    const { cookie } = await account("free");
    const res = await create(cookie, "form");
    expect(res.status).toBe(402);
    expect(((await res.json()) as { code: string }).code).toBe("forms_require_paid_plan");
  });

  it("counts forms apart from portals", async () => {
    const { user, cookie } = await account("pro");
    for (let i = 0; i < 3; i++) expect((await create(cookie)).status).toBe(201);
    for (let i = 0; i < 3; i++) expect((await create(cookie, "form")).status).toBe(201);

    const fourth = await create(cookie, "form");
    expect(fourth.status).toBe(409);
    expect(((await fourth.json()) as { code: string }).code).toBe("form_limit_reached");
    expect((await create(cookie)).status).toBe(409);
    expect(await db.select().from(portals).where(eq(portals.ownerId, user.id))).toHaveLength(6);
  });

  it("refuses a kind it does not know", async () => {
    const { cookie } = await account("pro");
    const res = await call(cookie, "POST", "/api/portals", {
      id: nanoid(),
      publicBundle: BUNDLE,
      sealedKeys: SEALED,
      depositToken: TOKEN,
      kind: "survey",
    });
    expect(res.status).toBe(400);
  });

  it("keeps portals made without a kind as portals", async () => {
    const { cookie } = await account("pro");
    const res = await create(cookie);
    const { id } = (await res.json()) as { id: string };
    const [row] = await db.select().from(portals).where(eq(portals.id, id));
    expect(row.kind).toBe("portal");
  });
});

describe("a response to a form", () => {
  async function formWithResponse(contentType: string, size = 1024) {
    const { cookie } = await account("pro");
    const formId = nanoid();
    await call(cookie, "POST", "/api/portals", {
      id: formId,
      publicBundle: BUNDLE,
      sealedKeys: SEALED,
      depositToken: TOKEN,
      kind: "form",
    });
    const pub = (await (await call(null, "GET", `/api/portals/${formId}/public`)).json()) as {
      kind: string;
      accepting: boolean;
    };
    expect(pub).toMatchObject({ kind: "form", accepting: true });

    const started = await call(null, "POST", `/api/portals/${formId}/deposits`, { depositToken: TOKEN });
    expect(started.status).toBe(201);
    const { transferId } = (await started.json()) as { transferId: string };
    const init = await call(null, "POST", "/api/upload/init-multipart", {
      transferId,
      size,
      contentType,
      ...FILE_FIELDS,
    });
    expect(init.status).toBe(200);
    const done = await call(null, "POST", "/api/upload/complete", { transferId, sealedKey: SEALED_KEY });
    expect(done.status).toBe(200);
    return { cookie, formId, transferId };
  }

  it("comes with a link to its answers file", async () => {
    const { cookie, formId, transferId } = await formWithResponse(ANSWERS_MIME_TYPE);
    const list = (await (await call(cookie, "GET", `/api/portals/${formId}/deposits`)).json()) as {
      deposits: { id: string; answersUrl?: string; files: unknown[] }[];
    };
    expect(list.deposits).toHaveLength(1);
    expect(list.deposits[0].id).toBe(transferId);
    expect(list.deposits[0].answersUrl).toContain(transferId);
    // The answers file is still listed; the reader hides it.
    expect(list.deposits[0].files).toHaveLength(1);
  });

  it("has no answers link when the answers file is too large to be one", async () => {
    const { cookie, formId } = await formWithResponse(ANSWERS_MIME_TYPE, ANSWERS_MAX_BYTES + 1);
    const list = (await (await call(cookie, "GET", `/api/portals/${formId}/deposits`)).json()) as {
      deposits: { answersUrl?: string; files: unknown[] }[];
    };
    expect(list.deposits[0].answersUrl).toBeUndefined();
    expect(list.deposits[0].files).toHaveLength(1);
  });

  it("has no answers link when no file is an answers file", async () => {
    const { cookie, formId } = await formWithResponse("application/octet-stream");
    const list = (await (await call(cookie, "GET", `/api/portals/${formId}/deposits`)).json()) as {
      deposits: { answersUrl?: string }[];
    };
    expect(list.deposits[0].answersUrl).toBeUndefined();
  });

  it("stops being accepted when the owner leaves the paid plans", async () => {
    const { user, formId } = await formWithResponse(ANSWERS_MIME_TYPE).then(async (made) => {
      const [row] = await db.select().from(portals).where(eq(portals.id, made.formId));
      return { user: { id: row.ownerId }, formId: made.formId };
    });
    await db.update(users).set({ tier: "free" }).where(eq(users.id, user.id));
    const pub = (await (await call(null, "GET", `/api/portals/${formId}/public`)).json()) as { accepting: boolean };
    expect(pub.accepting).toBe(false);
    const started = await call(null, "POST", `/api/portals/${formId}/deposits`, { depositToken: TOKEN });
    expect(started.status).toBe(403);
  });
});

describe("the arrival email", () => {
  it("speaks of a form and links to it", () => {
    const content = buildPortalNotice({ kind: "delivery", to: "a@example.com", portalId: "p".repeat(21), form: true });
    expect(content.subject).toContain("form");
    expect(content.button.url).toContain("/dashboard/forms/");
  });

  it("still speaks of files for a portal", () => {
    const content = buildPortalNotice({ kind: "delivery", to: "a@example.com", portalId: "p".repeat(21) });
    expect(content.subject).toContain("files");
    expect(content.button.url).toContain("/dashboard/portals/");
  });
});

describe("the sharing emails", () => {
  it("speak of a form and link to the forms", () => {
    const invited = buildPortalNotice({ kind: "invited", to: "a@example.com", ownerEmail: "o@example.com", form: true });
    expect(invited.subject).toContain("form");
    expect(invited.button.url).toContain("/dashboard/forms");
    const ready = buildPortalNotice({
      kind: "invitee_ready",
      to: "o@example.com",
      inviteeEmail: "a@example.com",
      portalId: "p".repeat(21),
      form: true,
    });
    expect(ready.button.url).toContain(`/dashboard/forms/${"p".repeat(21)}`);
    const given = buildPortalNotice({ kind: "access_given", to: "a@example.com", ownerEmail: "o@example.com" });
    expect(given.subject).toContain("portal");
    expect(given.button.url).toContain("/dashboard/portals");
  });
});
