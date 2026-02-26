const router = require('express').Router();
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const rateLimit = require("express-rate-limit");
const jwt = require('jsonwebtoken');


























const signInLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15, // max 5 attempts per window per IP
  message: {
    message: "Too many login attempts. Try again later."
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const jwtSecret = process.env.JWTSECRET




// --- Schema Definition ---
const adminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    idNumber: { type: String, required: true, unique: true }
});

console.log(
    'he'
)
const Admin = mongoose.model('Admin', adminSchema);

// --- Fixed addAdmin Function ---
async function addAdmin(username, password, idNumber) {
    try {
        // 1. Generate Salt
        const salt = await bcrypt.genSalt(10);
        
        // 2. Hash ONLY the password
        const hashedPassword = await bcrypt.hash(password, salt);
        const hashedUsername = await bcrypt.hash(username, salt);
        const hashedIdNumber = await bcrypt.hash(idNumber, salt)
        // 3. Create the document using the MODEL (Admin), not the schema
        const admin = new Admin({
            username: username, // Keep as plain text to allow searching
            password: hashedPassword,
            idNumber: idNumber // Usually kept as plain text or encrypted, but not hashed
        });

        // 4. Wait for the save to complete
        const savedAdmin = await admin.save();
        console.log('Admin saved successfully:', savedAdmin.username);
    } catch (err) {
        console.error('Error saving admin:', err.message);
    }
}

// Call the function
// addAdmin('ahmed' , 'kp8@.etiR?kowA' , '8192')


router.post('/api/sign', signInLimiter, async (req, res) => {
  try {
    // 1️⃣ Check body
    const data = req.body;
    if (!data || !data.idNumber || !data.password) {
      logger?.info('SignIn failed: missing idNumber or password');
      return sendError(res, 400, 'idNumber and password are required');
    }

    // 2️⃣ Find admin
    const admin = await Admin.findOne({ idNumber: data.idNumber });
    if (!admin) {
      logger?.info(`SignIn failed: Admin not found for idNumber ${data.idNumber}`);
      return sendError(res, 400, 'Wrong username or id');
    }

    // 3️⃣ Compare password
    let matchPassword;
    try {
      matchPassword = await bcrypt.compare(data.password, admin.password);
    } catch (bcryptErr) {
      logger?.error(`Bcrypt error for idNumber ${data.idNumber}: ${bcryptErr.stack}`);
      return sendError(res, 500, 'Server error during password verification');
    }

    if (!matchPassword) {
      logger?.info(`SignIn failed: Password mismatch for idNumber ${data.idNumber}`);
      return sendError(res, 400, 'Wrong username or password');
    }

    // 4️⃣ Generate JWT
    let jwtToken;
    try {
      jwtToken = jwt.sign(
        { userId: data.idNumber, username: admin.username },
        jwtSecret,
        { expiresIn: '1h' }
      );
    } catch (jwtErr) {
      logger?.error(`JWT signing error for idNumber ${data.idNumber}: ${jwtErr.stack}`);
      return sendError(res, 500, 'Server error during token creation');
    }

    // 5️⃣ Set cookie
    try {
      res.cookie('token', jwtToken, {
        httpOnly: true,
        secure: true, // HTTPS only
        sameSite: 'strict',
        maxAge: 3600000,
      });
    } catch (cookieErr) {
      logger?.error(`Cookie setting error for idNumber ${data.idNumber}: ${cookieErr.stack}`);
      // Not critical — still send token in JSON if needed
      return sendError(res, 500, 'Server error while setting authentication cookie');
    }

    logger?.info(`SignIn success for idNumber ${data.idNumber}`);
    return res.status(200).json({ message: 'success' });

  } catch (err) {
    // Catch any unexpected error
    logger?.error(`Unexpected error in /api/sign: ${err.stack}`);
    return sendError(res, 500, 'Internal server error');
  }
});

module.exports = router;
