import { PrismaClient } from "@prisma/client";
/**
 * Singleton Prisma client. Kept in one place so the whole pipeline shares a
 * pool and so tests can mock a single import.
 */
export declare const prisma: PrismaClient<{
    log: ({
        level: "warn";
        emit: "event";
    } | {
        level: "error";
        emit: "event";
    })[];
}, "error" | "warn", import("@prisma/client/runtime/library").DefaultArgs>;
export declare function disconnectDb(): Promise<void>;
