import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';

const port = 3000;
const app = express();

// CORS configuration
const corsOptions = {
  origin: 'https://3ae136ae-a5de-4351-85cc-4b56963af724-00-1bhn45hk2nnyl.sisko.replit.dev',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json({ limit: '50mb' }));

// Database connection
async function connectDB() {
  try {
    await mongoose.connect('mongodb+srv://alitalalfakhri0009:AoXTFVYzjtR48rGM@cluster0.j51q2rm.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0');
    console.log('Connected to MongoDB');
  } catch (err) {
    console.error('Database connection error:', err.message);
    process.exit(1); // Exit if DB connection fails
  }
}
connectDB();

// Product Schema and Model
const productSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Product name is required'],
    trim: true
  },
  price: {
    type: Number,
    required: [true, 'Price is required'],
    min: [0, 'Price cannot be negative']
  },
  description: {
    type: String,
    default: 'No description provided',
    trim: true
  },
  image: {
    type: String,
    required: [true, 'Image is required']
  },
  origin: {
    type: String,
    default: 'Unknown origin',
    trim: true
  },
  hasSizes: {
    type: Boolean,
    default: false
  },
  sizes: {
    type: [String],
    default: [],
    validate: {
      validator: function(sizes) {
        return !this.hasSizes || sizes.length > 0;
      },
      message: 'At least one size is required when hasSizes is true'
    }
  },
  category:{
    type: String,
    required: [true, 'Category is required'],
  },
  stock: {
    type: String,
  
  
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Product = mongoose.model('Product', productSchema);

// Routes
app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.post('/add/product', async (req, res) => {
  try {
    // Validate request body
    if (!req.body) {
      return res.status(400).json({ error: 'Request body is missing' });
    }

    // Create new product
    const product = new Product(req.body);
    await product.save();

    // Send success response
    res.status(201).json({
      message: 'Product added successfully',
      product: {
        id: product._id,
        name: product.name,
        price: product.price,
        image: product.image ? 'Image uploaded' : null,
        sizes: product.sizes
      }
    });
  } catch (err) {
    console.error('Error adding product:', err);

    // Handle validation errors
    if (err.name === 'ValidationError') {
      const errors = Object.values(err.errors).map(e => e.message);
      return res.status(400).json({ error: 'Validation error', details: errors });
    }

    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// Error handling middleware


app.get('/api/products' , async (req, res) =>{
  try{
    const products = await Product.find();
    res.json(products);
  }catch(err){
    res.status(500).json({error: 'Server error', details: err.message})
  }
})
// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});