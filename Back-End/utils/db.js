import dotenv from "dotenv";
import mysql from "mysql2";

dotenv.config();

const db = mysql.createConnection({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "gamage_recruiters_db",

});

db.connect(err => {
    if (err) {
        console.error("Database connection failed:", err);
        process.exit(1);
    } else {
        console.log("✅ Connected to MySQL Database");
    }
});

export default db;
