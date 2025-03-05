import db from "../utils/db.js";
import bcrypt from "bcryptjs";

export const registerUser = async (req, res) => { 
    const { name, email, password, confirmPassword, isAdmin = false } = req.body;

    if (!name || !email || !password || !confirmPassword) {
        return res.status(400).json({ message: "All fields are required" });
    }

    if (password !== confirmPassword) {
        return res.status(400).json({ message: "Passwords do not match" });
    }

    try {
        // Check if email already exists
        db.query('SELECT * FROM user WHERE email = ?', [email], async (err, result) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ error: "Internal Server Error" });
            }

            if (result.length > 0) {
                return res.status(400).json({ message: "Email already exists" });
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            db.query(
                "INSERT INTO user (name, email, password, isAdmin) VALUES (?, ?, ?, ?)",
                [name, email, hashedPassword, isAdmin],
                (err, result) => {
                    if (err) {
                        console.error("Database insertion error:", err);
                        return res.status(500).json({ error: "Internal Server Error" });
                    }

                    res.status(201).json({ message: "User Registered successfully" });
                }
            );
        });
    } catch (error) {
        console.error("Unexpected error:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
};
