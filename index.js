const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const rateLimiter = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const prductsRoute = require("./routers/products")
const adminroute = require('./routers/admin')
const dns = require('node:dns')

dns.setServers([
  '8.8.8.8',
]);

const limiter = rateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
  headers: true,
  standardHeaders: true,
  legacyHeaders: false,
})


//516Q6wXpUU8U02mQ
//altaifproject09_db_user
const app = express();
const port = 5000;
app.use(express.json());
app.use(cors({
  origin: ['https://temp-admin-silk.vercel.app' , 'https://temp-client-three.vercel.app'], // Ensure this matches your client's URL
  credentials: true
}));

app.use(cookieParser())

app.use(limiter);

const URI = process.env.URI
  mongoose.connect(URI)
  .then(() => {
    console.log('✅ Connected to the database');
  })
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err.message);
  });

app.use(prductsRoute)

app.use(adminroute)


app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});
