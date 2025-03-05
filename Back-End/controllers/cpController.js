import db from '../utils/db.js';
import bcrypt from 'bcrypt';

export const changePassword = async (req, res) => {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
        return res.status(400).json({ message: 'Email and new password are required' });
    }

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        db.query(
            'UPDATE users SET password = ? WHERE email = ?',
            [hashedPassword, email],
            (err, result) => {
                if (err) return res.status(500).json({ message: 'Database error', error: err });

                if (result.affectedRows === 0) {
                    return res.status(404).json({ message: 'User not found' });
                }

                res.status(200).json({ message: 'Password updated successfully' });
            }
        );
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
};
