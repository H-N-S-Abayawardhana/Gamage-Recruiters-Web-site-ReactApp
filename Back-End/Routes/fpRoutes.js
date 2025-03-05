import express from 'express';
import { forgotPassword } from '../controllers/fpController.js'; 

const router = express.Router();

router.post('/forgotpassword', forgotPassword);

export default router;