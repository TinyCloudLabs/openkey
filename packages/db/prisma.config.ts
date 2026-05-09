import "dotenv/config";
import path from "node:path";
import { defineConfig } from "prisma/config";

const databaseUrl = process.env.DATABASE_URL?.startsWith("pglite:")
  ? "postgresql://openkey:openkey@localhost:5432/openkey"
  : process.env.DATABASE_URL ?? "postgresql://openkey:openkey@localhost:5432/openkey";

export default defineConfig({
  schema: path.join(__dirname, "prisma/schema.prisma"),
  migrations: {
    path: path.join(__dirname, "prisma/migrations"),
  },
  datasource: {
    url: databaseUrl,
  },
});
