import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import transporter from '../config/mailer.js';

const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// **Send OTP to Email**
exports.forgotPassword = (req, res) => {
  const { email } = req.body;
  const otp = generateOTP();

  User.findByEmail(email, (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (results.length === 0) return res.status(404).json({ message: 'User not found' });

    User.updateOTP(email, otp, err => {
      if (err) return res.status(500).json({ message: 'Error saving OTP' });

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Password Reset OTP',
        text: `Your OTP for password reset is: ${otp}`,
      };

      transporter.sendMail(mailOptions, err => {
        if (err) return res.status(500).json({ message: 'Error sending OTP' });
        res.json({ message: 'OTP sent successfully' });
      });
    });
  });
};

//  **Verify OTP**
exports.verifyOTP = (req, res) => {
  const { email, otp } = req.body;

  User.verifyOTP(email, otp, (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (results.length === 0) return res.status(400).json({ message: 'Invalid OTP' });

    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '10m' });
    res.json({ message: 'OTP verified', token });
  });
};

// **Reset Password**
exports.resetPassword = (req, res) => {
  const { email, newPassword, token } = req.body;

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(400).json({ message: 'Invalid or expired token' });

    bcrypt.hash(newPassword, 10, (err, hash) => {
      if (err) return res.status(500).json({ message: 'Error hashing password' });

      User.updatePassword(email, hash, err => {
        if (err) return res.status(500).json({ message: 'Error updating password' });

        res.json({ message: 'Password reset successfully' });
      });
    });
  });
};