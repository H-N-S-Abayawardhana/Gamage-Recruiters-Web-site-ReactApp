import express from 'express';
import { changePassword } from '../controllers/cpController.js'; 

const router = express.Router();

router.post('/change', changePassword);

export default router;
