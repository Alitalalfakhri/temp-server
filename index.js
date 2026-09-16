const express = require('express');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const cors = require('cors');
const rateLimiter = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const prductsRoute = require("./routers/products")
const adminroute = require('./routers/admin')
const mediaRoute = require('./routers/media')
const dns = require('node:dns')
const path = require('path')
const fs = require('fs')
dotenv.config();
/*dns.setServers([
  '8.8.8.8',
]);*/

const limiter = rateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  message: 'Too many requests from this IP, please try again later.',
  headers: true,
  standardHeaders: true,
  legacyHeaders: false,
})


const app = express();
const port = process.env.PORT || 5000;
app.use(express.json());
app.use(cors({
  origin: ['https://temp-admin-silk.vercel.app' , 'https://temp-client-three.vercel.app', 'http://localhost:3000' , 'http://localhost:3001'], // Ensure this matches your client's URL
  credentials: true
}));

app.use(cookieParser())

app.use(limiter);

const URI = process.env.URI;

if (!URI) {
  console.error('❌ Missing URI in server/.env');
  process.exit(1);
}

mongoose.connect(URI)
  .then(() => {
    console.log('✅ Connected to the database');
  })
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err);
  });

  const uploadsPath = path.join(__dirname, "uploads");


app.use("/uploads", express.static(uploadsPath));

app.use(prductsRoute)

app.use(adminroute)

app.use(mediaRoute)

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});
