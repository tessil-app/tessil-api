// Single-transfer passes: a one-time payment that lets one transfer
// through the paywall. The browser keeps a random token; we keep its
// hash and the Polar checkout it belongs to.

import { createHash, randomBytes } from "node:crypto";
import { and, eq, isNull, lt, sql } from "drizzle-orm";
import { nanoid } from "nanoid";
import { db } from "../db";
import { transferPasses, transfers, type TransferPass } from "../db/schema";
import { createPassCheckout, isPassCheckoutPaid } from "./polar.service";

// A retry after a failed upload must not need a second payment, so a
// pass may back a few unfinished transfers. Only one can complete.
const MAX_OPEN_TRANSFERS_PER_PASS = 3;

const UNPAID_PASS_TTL_HOURS = 24;

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** Open a Polar checkout and the pass row waiting on it. */
export async function createPass(): Promise<{ token: string; url: string }> {
  const { url, checkoutId } = await createPassCheckout();
  const token = randomBytes(32).toString("base64url");
  await db.insert(transferPasses).values({
    id: nanoid(),
    tokenHash: hashToken(token),
    polarCheckoutId: checkoutId,
  });
  return { token, url };
}

async function findPass(token: string): Promise<TransferPass | null> {
  const [pass] = await db
    .select()
    .from(transferPasses)
    .where(eq(transferPasses.tokenHash, hashToken(token)))
    .limit(1);
  return pass ?? null;
}

export type PassState = "unknown" | "unpaid" | "paid" | "used";

/**
 * Resolve a token to its pass, asking Polar when we have not yet seen
 * the payment. There is no webhook for passes: the buyer's own browser
 * polls, which keeps the checkout free of any customer identifier.
 */
export async function resolvePass(
  token: string,
): Promise<{ state: PassState; pass: TransferPass | null }> {
  const pass = await findPass(token);
  if (!pass) return { state: "unknown", pass: null };
  if (pass.consumedAt) return { state: "used", pass };
  if (pass.paidAt) return { state: "paid", pass };

  if (!(await isPassCheckoutPaid(pass.polarCheckoutId))) {
    return { state: "unpaid", pass };
  }
  const paidAt = new Date();
  await db
    .update(transferPasses)
    .set({ paidAt })
    .where(and(eq(transferPasses.id, pass.id), isNull(transferPasses.paidAt)));
  return { state: "paid", pass: { ...pass, paidAt } };
}

export async function hasOpenTransferSlot(passId: string): Promise<boolean> {
  const [row] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(transfers)
    .where(
      and(
        eq(transfers.passId, passId),
        eq(transfers.isDeleted, false),
        eq(transfers.isCompleted, false),
      ),
    );
  return (row?.count ?? 0) < MAX_OPEN_TRANSFERS_PER_PASS;
}

export class PassAlreadyUsedError extends Error {
  constructor() {
    super("Pass already used");
  }
}

/**
 * Spend the pass and mark the transfer complete in one transaction, so
 * a pass is never burnt without a live transfer to show for it. Clears
 * the transfer's pointer to the pass on the way out.
 */
export async function completeTransferWithPass(
  transferId: string,
  passId: string,
  vaultWrap?: { wrappedKey: Uint8Array },
): Promise<void> {
  await db.transaction(async (tx) => {
    const spent = await tx
      .update(transferPasses)
      .set({ consumedAt: new Date() })
      .where(and(eq(transferPasses.id, passId), isNull(transferPasses.consumedAt)))
      .returning({ id: transferPasses.id });
    if (spent.length === 0) throw new PassAlreadyUsedError();

    await tx
      .update(transfers)
      .set({
        isCompleted: true,
        passId: null,
        ...(vaultWrap ? { wrappedKey: vaultWrap.wrappedKey } : {}),
      })
      .where(eq(transfers.id, transferId));
  });
}

/** Drop checkouts that were opened and never paid. */
export async function cleanupUnpaidPasses(): Promise<number> {
  const cutoff = new Date(Date.now() - UNPAID_PASS_TTL_HOURS * 60 * 60 * 1000);
  const deleted = await db
    .delete(transferPasses)
    .where(and(isNull(transferPasses.paidAt), lt(transferPasses.createdAt, cutoff)))
    .returning({ id: transferPasses.id });
  return deleted.length;
}
