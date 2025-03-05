import db from "../utils/db.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Generate JWT Token
const generateToken = (user) => {
  return jwt.sign(
    { id: user.id, email: user.email, isAdmin: user.isAdmin },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
};

// Regular Email/Password Login
export const loginUser = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  try {
    db.query("SELECT * FROM user WHERE email = ?", [email], async (err, result) => {
      if (err) return res.status(500).json({ error: err.message });

      if (result.length === 0) {
        return res.status(400).json({ message: "User not found" });
      }

      const user = result[0];

      // Compare passwords
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: "Invalid credentials" });
      }

      // Generate token
      const token = generateToken(user);

      // Successful login
      res.status(200).json({
        message: "Login successful",
        email: user.email, // Include email in response
        user: { id: user.id, email: user.email, name: user.name, isAdmin: user.isAdmin },
        token,
      });
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Google Sign-In
export const googleLogin = async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ message: "Google token is required" });
  }

  try {
    // Verify the Google token
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { email, name, picture } = payload;

    // Check if the user already exists in the database
    db.query("SELECT * FROM user WHERE email = ?", [email], async (err, result) => {
      if (err) return res.status(500).json({ error: err.message });

      let user;

      if (result.length === 0) {
        // If the user doesn't exist, create a new user
        const newUser = {
          name,
          email,
          password: null, // No password for Google users
          isAdmin: false,
          profilePicture: picture,
        };

        db.query(
          "INSERT INTO user (name, email, password, isAdmin, profilePicture) VALUES (?, ?, ?, ?, ?)",
          [newUser.name, newUser.email, newUser.password, newUser.isAdmin, newUser.profilePicture],
          (insertErr, insertResult) => {
            if (insertErr) return res.status(500).json({ error: insertErr.message });

            user = { id: insertResult.insertId, ...newUser };

            // Generate token
            const authToken = generateToken(user);

            res.status(200).json({ 
              message: "Google login successful", 
              email: user.email, // Include email in response
              user, 
              token: authToken 
            });
          }
        );
      } else {
        // If the user exists, return the user data
        user = result[0];

        // Generate token
        const authToken = generateToken(user);

        res.status(200).json({ 
          message: "Google login successful", 
          email: user.email, // Include email in response
          user, 
          token: authToken 
        });
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
