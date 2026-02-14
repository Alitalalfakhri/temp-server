const mongoose = require("mongoose");

function generateRandomId() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let id = '';
    for (let i = 0; i < 15; i++) {
        const randomIndex = Math.floor(Math.random() * chars.length);
        id += chars[randomIndex];
    }
    return id;
}


const ProductSchema = new mongoose.Schema({
  id: {
    type: String,
    default: generateRandomId,
    unique: true,
  },
  title: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
  sizes:{
    type: Array,
    required: true,
    default:undefined
  },
  imageLink:{
    type: String,
    required: true,
    
  }
});

const Product = mongoose.model("Product", ProductSchema);

module.exports = Product;