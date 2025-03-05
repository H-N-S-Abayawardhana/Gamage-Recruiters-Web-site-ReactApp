import express from 'express'; 
import cors from 'cors';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';
import db from './utils/db.js';
import userRoutes from "./Routes/UserRoutes.js";  
import loginRoutes from "./Routes/LoginRoutes.js";
import fpRoutes from './Routes/fpRoutes.js';
import otpRoutes from './Routes/otpRoutes.js';
import cpRoutes from './Routes/cpRoutes.js';
import authRoutes from './Routes/authRoutes.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 7000; // Use the PORT from .env, fallback to 7000 if undefined

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Test Route
app.get("/", (req, res) => {
    res.send("Backend is running!");
});

// API Route to Store Code in Database
app.post("/api/enter-code", (req, res) => {
    const { code } = req.body;

    if (!code) {
        return res.status(400).json({ error: "Code is required" });
    }

    const query = "INSERT INTO codes (code) VALUES (?)";

    db.query(query, [code], (err, result) => {
        if (err) {
            console.error("Error inserting code:", err);
            return res.status(500).json({ error: "Database error" });
        }
        res.status(201).json({ message: "Code saved successfully", id: result.insertId });
    });
});

// Routes
app.use('/api/user', userRoutes);
app.use('/api/auth', fpRoutes);
app.use('/api/otp', otpRoutes);
app.use('/api/password', cpRoutes);
app.use('/api/user', loginRoutes);
app.use('/api/auth', authRoutes);

// Start Server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
