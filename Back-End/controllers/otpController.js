import db from '../utils/db.js';

export const verifyOTP = async (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).json({ message: 'Email and OTP are required' });
    }

    db.query('SELECT * FROM password_reset_requests WHERE email = ? ORDER BY requested_at DESC LIMIT 1', [email], (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error' });

        if (results.length === 0) {
            return res.status(400).json({ message: 'No OTP found for this email' });
        }

        const { otp: storedOTP, expires_at } = results[0];

        if (new Date() > new Date(expires_at)) {
            return res.status(400).json({ message: 'OTP expired' });
        }

        if (storedOTP !== otp) {
            return res.status(400).json({ message: 'Invalid OTP' });
        }

        res.status(200).json({ message: 'OTP verified successfully' });
    });
};
