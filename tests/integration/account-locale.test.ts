// The language an account chooses: kept on the account, returned with it,
// and only one of the languages the site has.

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { createApp } from "../../src/app";
import { authedRequest, createAuthedUser } from "../helpers/auth";
import { ensureMigrations, resetDb } from "../helpers/db";

const APP_URL = process.env.APP_URL!;
let app: ReturnType<typeof createApp>;

beforeAll(async () => {
  await ensureMigrations();
  app = createApp();
});
beforeEach(resetDb);
afterAll(resetDb);

const setLocale = (cookie: string | null, locale: unknown) => {
  const init = { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ locale }) };
  return app.handle(
    cookie
      ? authedRequest(cookie, `${APP_URL}/api/me/locale`, init)
      : new Request(`${APP_URL}/api/me/locale`, { ...init, headers: { ...init.headers, Origin: APP_URL } }),
  );
};
const me = async (cookie: string) =>
  ((await (await app.handle(authedRequest(cookie, `${APP_URL}/api/auth/me`))).json()) as { user: { locale: string | null } })
    .user;

describe("an account's language", () => {
  it("is not chosen until the account chooses one", async () => {
    const { cookie } = await createAuthedUser();
    expect((await me(cookie)).locale).toBeNull();
  });

  it("is kept, returned with the account, and can be cleared", async () => {
    const { cookie } = await createAuthedUser();
    expect((await setLocale(cookie, "nl")).status).toBe(200);
    expect((await me(cookie)).locale).toBe("nl");
    expect((await setLocale(cookie, null)).status).toBe(200);
    expect((await me(cookie)).locale).toBeNull();
  });

  it("is only one the site has, and needs an account", async () => {
    const { cookie } = await createAuthedUser();
    expect((await setLocale(cookie, "de")).status).toBe(400);
    expect((await setLocale(cookie, "")).status).toBe(400);
    expect((await setLocale(null, "nl")).status).toBe(401);
  });
});
