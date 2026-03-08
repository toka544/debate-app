require("dotenv").config();
const fs = require("fs");
const { Client } = require("pg");

function formatDbError(err) {
  if (!err) return "Unknown database error";
  if (Array.isArray(err.errors) && err.errors.length) {
    return err.errors
      .map((e) =>
        [e.code, e.address && e.port ? `${e.address}:${e.port}` : "", e.message]
          .filter(Boolean)
          .join(" ")
      )
      .join(" | ");
  }
  return err.message || err.code || String(err);
}

async function run() {
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: (process.env.DATABASE_URL || "").includes("render.com")
      ? { rejectUnauthorized: false }
      : undefined,
  });
  try {
    await client.connect();
    console.log("✅ Connected to DB");
    await client.query(fs.readFileSync("./db.sql", "utf8"));
    console.log("✅ Migration complete");
  } catch (err) {
    console.error("❌ Migration failed:", formatDbError(err));
    if (err?.code === "ECONNREFUSED") {
      console.error("ℹ️ Postgres is not reachable. Check DATABASE_URL and make sure DB server is running.");
    }
    process.exit(1);
  } finally {
    await client.end().catch(() => {});
  }
}

run();
