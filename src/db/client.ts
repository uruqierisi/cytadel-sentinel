import { PrismaClient } from "@prisma/client";
import { logger } from "../lib/logger.js";

/**
 * Singleton Prisma client. Kept in one place so the whole pipeline shares a
 * pool and so tests can mock a single import.
 */
export const prisma = new PrismaClient({
  log: [
    { level: "warn", emit: "event" },
    { level: "error", emit: "event" },
  ],
});

prisma.$on("warn", (e) => logger.warn({ prisma: e }, "prisma warning"));
prisma.$on("error", (e) => logger.error({ prisma: e }, "prisma error"));

export async function disconnectDb(): Promise<void> {
  await prisma.$disconnect();
}
