// Emails to a portal's or form's members that something arrived, when the
// owner asked for them. The first delivery is announced at once; after that
// at most one email per interval, which says how many arrived meanwhile.

import { mailLocale, sendPortalNotice } from "./email.service";
import { claimDeliveryNotice, getPortal, portalsOwedNotice } from "./portal.service";

/** Never throws: the delivery has already succeeded. */
export async function notifyOfDelivery(portalId: string, source: "arrival" | "sweep" = "arrival"): Promise<void> {
  try {
    const notice = await claimDeliveryNotice(portalId);
    if (!notice || notice.recipients.length === 0) return;
    // An arrival is at least itself, whatever the count read a moment later.
    const count = source === "arrival" ? Math.max(1, notice.count) : notice.count;
    if (count === 0) return;
    const form = (await getPortal(portalId))?.kind === "form";
    await Promise.all(
      notice.recipients.map((r) =>
        sendPortalNotice({ kind: "delivery", to: r.email, portalId, form, count, locale: mailLocale(r.locale) }),
      ),
    );
  } catch (err) {
    console.error("[portal] delivery notice failed", err instanceof Error ? err.message : err);
  }
}

/** Announces what arrived during a quiet interval that has now passed. */
export async function sweepDeliveryNotices(): Promise<number> {
  const owed = await portalsOwedNotice();
  for (const portalId of owed) await notifyOfDelivery(portalId, "sweep");
  return owed.length;
}

export function startDeliveryNoticeSweep(): void {
  const INTERVAL_MS = 60 * 1000;
  let running = false;
  setInterval(async () => {
    if (running) return;
    running = true;
    try {
      await sweepDeliveryNotices();
    } catch (err) {
      console.error("[portal] delivery notice sweep failed", err instanceof Error ? err.message : err);
    } finally {
      running = false;
    }
  }, INTERVAL_MS);
}
