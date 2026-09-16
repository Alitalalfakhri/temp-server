const Product = require('../models/product');

const router = require('express').Router();

const imagekit = require('./iamgekit')

const upload = require('./multer')
const fs = require('fs/promises')
const path = require('path')

const dotenv = require('dotenv');

dotenv.config();

const cookieParser = require('cookie-parser');

const jwt = require('jsonwebtoken');

const { body, validationResult } = require('express-validator');




function authenticate(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Access denied" });

  try {
    const decoded = jwt.verify(token, process.env.JWTSECRET);
    req.user = decoded; // attach user info to request
    next();
  } catch (err) {
    res.status(403).json({ error: "Invalid or expired token" });
  }
}

router.get('/api/products' , (req , res) => {
    Product.find()
    .then(products => res.json(products))
    .catch(err => res.status(400).json('Error: ' + err));

    
})


router.post(
    "/api/add/product",
    authenticate,
    upload.single("image"),

    body("title").notEmpty().withMessage("title is required"),
    

    async (req, res) => {
        const productData = req.body;
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            if (!req.file) {
                return res.status(400).json({ message: "No image provided" });
            }

            let sizes = productData.sizes;

            if (typeof sizes === "string") {
                try {
                    sizes = JSON.parse(sizes);
                } catch (err) {
                    return res.status(400).json({ message: "Invalid sizes" });
                }
            }

            // The image is already saved by Multer
            const imageLink = `/uploads/products/${req.file.filename}`;

            const product = new Product({
                title: productData.title,
                description: productData.description,
                sizes: sizes,
                imageLink: imageLink,
                id: req.file.filename,
                videoLink: productData.videoLink || "",
            });

            await product.save();

            res.json({
                message: "Product added!",
                product
            });

        } catch (error) {
            res.status(500).json({
                message: "Upload failed",
                error: error.message
            });
        }
    }
);


// GET single product
router.get("/api/product/:id", async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "Not found" });
    res.json(product);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});



// UPDATE product
router.put("/api/product/edit/:id", authenticate, upload.single("image"), async (req, res) => {
    let newlyUploadedFileId = null;



    try {
        const product = await Product.findById(req.params.id);
        if (!product) return res.status(404).json({ message: "Not found" });

        // This 'id' is now the real ImageKit fileId we saved in the POST route
        const oldImageId = product.id; 

        product.title = req.body.title || product.title;
        product.description = req.body.description || product.description;
        if (req.body.sizes) product.sizes = JSON.parse(req.body.sizes);
        if (req.body.videoLink !== undefined) product.videoLink = req.body.videoLink || "";

        if (req.file) {
            // 1. Upload new image
            const result = await imagekit.upload({
                file: await fs.readFile(req.file.path),
                fileName: `product_${Date.now()}`,
                folder: "/products",
            });

            newlyUploadedFileId = result.fileId;
            product.imageLink = result.url;
            product.id = result.fileId; // Update DB with the NEW fileId
            await fs.unlink(req.file.path);
        }

        // 2. Save DB changes
        await product.save();

        // 3. Delete old file from ImageKit only AFTER DB success
        if (req.file && oldImageId) {
            await imagekit.deleteFile(oldImageId);
        }

        res.json({ message: "Updated successfully", product });
    } catch (err) {
        // Rollback: delete the new image if DB save fails
        if (newlyUploadedFileId) await imagekit.deleteFile(newlyUploadedFileId);
        res.status(500).json({ message: "Update failed", error: err.message });
    }
});

// 1. Fixed the typo in "product"
router.delete('/api/product/:id', authenticate ,async (req, res) => {
    try {
        const mongoId = req.params.id;

        // 1. Find the product to get the ImageKit fileId stored in the DB
        const product = await Product.findById(mongoId);
        
        if (!product) {
            return res.status(404).json('Product not found');
        }

        // Products added through Multer use a local upload path. Edited products
        // may instead point to an ImageKit file.
        try {
            if (product.imageLink?.startsWith('/uploads/products/')) {
                const localImagePath = path.join(__dirname, '..', product.imageLink);
                await fs.unlink(localImagePath);
            } else if (product.id) {
                await imagekit.deleteFile(product.id);
            }
        } catch (cleanupError) {
            console.error("Image cleanup failed:", cleanupError);
        }

        // The database record must not remain when image cleanup fails.
        await Product.findByIdAndDelete(mongoId);

        res.json('Product and associated image deleted successfully.');
        
    } catch (err) {
        console.error("Delete Error:", err);
        res.status(400).json({ message: "Deletion failed", error: err.message });
    }
});


module.exports = router;
