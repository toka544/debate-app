import fs from "fs";
import pkg from "pg";
const { Client } = pkg;

const client = new Client({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function run() {
  try {
    await client.connect();
    console.log("Connected to DB");

    const sql = fs.readFileSync("./db.sql").toString();

    await client.query(sql);

    console.log("Migration complete");
  } catch (err) {
    console.error(err);
  } finally {
    await client.end();
  }
}

run();