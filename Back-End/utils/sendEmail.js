const nodemailer = require('nodemailer');
require('dotenv').config();

const sendEmail = async (email, otp) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Password Reset Code',
        text: `Your OTP code for password reset is: ${otp}`
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`Email sent to ${email}`);
        return true;
    } catch (error) {
        console.error('Error sending email:', error);
        return false;
    }
};

module.exports = sendEmail;
