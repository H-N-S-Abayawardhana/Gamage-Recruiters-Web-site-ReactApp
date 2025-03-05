import db from '../utils/db.js';
import crypto from 'crypto';
import nodemailer from 'nodemailer';

const EMAIL_USER = 'your-email@gmail.com';  // Replace with your actual email
const EMAIL_PASS = 'your-app-password';  // Replace with your actual app password

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS
    }
});

// Generate OTP
const generateOTP = () => crypto.randomInt(100000, 999999).toString();

export const forgotPassword = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: 'Email is required' });
    }

    db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error', error: err });

        if (results.length === 0) {
            return res.status(200).json({ message: 'If this email exists, an OTP has been sent.' }); 
        }

        const otp = generateOTP();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // OTP expires in 10 minutes

        db.query('INSERT INTO password_reset_requests (email, otp, expires_at) VALUES (?, ?, ?)', 
            [email, otp, expiresAt], 
            (err) => {
                if (err) return res.status(500).json({ message: 'Error storing OTP' });

                // Send OTP via email
                const mailOptions = {
                    from: EMAIL_USER,
                    to: email,
                    subject: 'Password Reset OTP',
                    text: `Your OTP for password reset is: ${otp}. It is valid for 10 minutes.`
                };

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.error('Email Error:', error);  // Log the full error in the console
                        return res.status(500).json({ message: 'Error sending OTP email', error: error.message });
                    }
                    res.status(200).json({ message: 'If this email exists, an OTP has been sent.' });
                });
            }
        );
    });
};
