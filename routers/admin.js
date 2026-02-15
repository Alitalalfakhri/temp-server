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

router.post('/api/sign', signInLimiter,async(req , res) => {
    const data = req.body;

    const admin = await Admin.findOne({idNumber : data.idNumber})
    if(admin){
        const matchPassword = await bcrypt.compare(data.password , admin.password)
        if(matchPassword){
            const jwtToken = jwt.sign(
                {userId:data.idNumber , username:data.username},
                jwtSecret,
                {expiresIn:'1h'}
            )
             res.cookie('token', jwtToken, {
                httpOnly: true,
                secure: true,      // set true in production with HTTPS
                sameSite: 'strict', // protects against CSRF
                maxAge: 3600000     // 1 hour
            });

           

            return res.status(200).json('success')
        }
        else{
            res.status(400).json({message:'wrong username or password'})
        }
    }else{
        res.status(400).json({message:'wrong username or id'})
    }
 })



 router.get('/api/auth/check', (req, res) => {
  const token = req.cookies?.token;

  if (!token) return res.status(401).json({ authenticated: false });

  try {
    const decoded = jwt.verify(token, jwtSecret);
    res.json({ authenticated: true, username: decoded.username });
  } catch (err) {
    res.status(403).json({ authenticated: false });
  }
});

module.exports = router;