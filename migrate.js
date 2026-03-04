const fs = require("fs");
const { Client } = require("pg");

async function run() {
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL?.includes("render.com")
      ? { rejectUnauthorized: false }
      : undefined,
  });

  try {
    await client.connect();
    console.log("✅ Connected to DB");

    const sql = fs.readFileSync("./db.sql", "utf8");
    await client.query(sql);

    console.log("✅ Migration complete");
  } catch (err) {
    console.error("❌ Migration failed:", err);
    process.exitCode = 1;
  } finally {
    await client.end().catch(() => {});
  }
}

run();