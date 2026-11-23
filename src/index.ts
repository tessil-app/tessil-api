import { createApp } from "./app";
import { env } from "./config/env";
import { startCleanupJob } from "./services/cleanup.service";
import { startDeliveryNoticeSweep } from "./services/deliveryNotice.service";
import { flushLegacyRateLimitKeys } from "./services/ratelimit.service";
import { initIpContext } from "./utils/ipContext";

// MMDB readers + legacy-key flush before listen so the first request
// resolves a real IpContext and doesn't see stale raw-IP-keyed counters.
await initIpContext();
const flushed = await flushLegacyRateLimitKeys();
if (flushed > 0) {
  console.log(`[startup] flushed ${flushed} legacy rate-limit keys`);
}

const app = createApp().listen({
  port: env.PORT,
  maxRequestBodySize: 1024 * 1024 * 10, // 10MB — metadata only; files go directly to R2.
});

startCleanupJob();
startDeliveryNoticeSweep();

console.log(
  `Tessil API running at ${app.server?.hostname}:${app.server?.port}`,
);
