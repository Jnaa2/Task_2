import jwt from 'jsonwebtoken';
import { User } from '../models/User.js';

export function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const [, token] = authHeader.split(' '); // "Bearer <token>"
  if (!token) return res.status(401).json({ message: 'Missing token' });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    return next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

// ✅ Optional safety middleware to check user existence (no change to your current logic)
export async function verifyUserExists(req, res, next) {
  try {
    if (!req.user?.id) return res.status(401).json({ message: 'Unauthorized' });

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    next();
  } catch (error) {
    return res.status(500).json({ message: 'Error verifying user' });
  }
}
