import express from "express";
import { loginUser, googleLogin } from "../controllers/LoginControllers.js";

const router = express.Router();

// Regular Email/Password Login
router.post("/login", loginUser);

// Google Sign-In
router.post("/google-login", googleLogin);

export default router;