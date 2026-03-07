require("dotenv").config();
const fs = require("fs");
const { Client } = require("pg");

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
    console.error("❌ Migration failed:", err.message);
    process.exit(1);
  } finally {
    await client.end().catch(() => {});
  }
}

run();