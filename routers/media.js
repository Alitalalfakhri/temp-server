
const router = require('express').Router();
const jwt = require('jsonwebtoken');

const imagekit = require('./iamgekit')

const upload = require('./multer')

const dotenv = require('dotenv');

dotenv.config();

const ReviewVideos = require('../models/reviewVideo')

const FactoryVideos = require('../models/factoryVideos')

const FactoryImage = require('../models/factoryImages')


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


router.post("/api/add/video", authenticate,async (req, res) =>{
    const videoData = req.body;
   
    if(!videoData.videoType){
        return res.json({message:"no video type "}).status(400)

    }
    if(videoData.videoType === 'review'){
         if(!videoData.videoUrl ){
        return res.json({message:"no video url  "}).status(400)
    }
        const video = new ReviewVideos({
            videoUrl:videoData.videoUrl,
            description:videoData.description,
            role:videoData.role,
            company:videoData.company
        })
        await video.save()
        return res.json({message:"video added"}).status(200)

    }
    if(videoData.videoType === 'factory'){
        const video = new FactoryVideos({
            videoUrl:videoData.videoUrl,
            
        })
        await video.save()
        return res.json({message:"video added"}).status(200)

    }
    }
);

router.get('/api/reviews/videos' , async(req , res) => {
    const videos = await ReviewVideos.find()
    res.json(videos)
})

router.get('/api/factory/videos' , async(req , res) => {
    const videos = await FactoryVideos.find()
    res.json(videos)
})



/*router.post("/api/add/image" , upload.single("image") ,async (req, res) =>{
    
   if(!req.file){
    return res.json({message:"no image "}).status(400)
   }
   else{
      const result = await imagekit.upload({
                file: req.file.buffer,
                fileName: `img_library${Date.now()}`, // Added timestamp to avoid naming collisions
                folder: "/library",
            });

     const image = FactoryImage({
        imageUrl:result.url
     })
     await image.save()
     return res.json({message:"image added"}).status(200)
   }
})*/

router.post("/api/add/image", upload.single("image"), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: "no image" });
    }

    try {
        const result = await imagekit.upload({
            file: req.file.buffer,
            fileName: `img_library${Date.now()}`,
            folder: "/library",
        });

        const image = new FactoryImage({
            imageUrl: result.url,
            fileId: result.fileId,  
            title: req.body.title,
        });

        await image.save();
        return res.status(200).json({ message: "image added" });

    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Upload failed", error: err.message });
    }
});


router.get('/api/images' , async(req , res) => {
    const images = await FactoryImage.find()
    res.json(images)

})
// Delete a video by ID
router.delete("/api/delete/video/:id", authenticate, async (req, res) => {
    const videoId = req.params.id;

    try {
        // Try deleting from ReviewVideos first
        let deleted = await ReviewVideos.findByIdAndDelete(videoId);
        if (!deleted) {
            // If not found in ReviewVideos, try FactoryVideos
            deleted = await FactoryVideos.findByIdAndDelete(videoId);
        }

        if (!deleted) {
            return res.status(404).json({ message: "Video not found" });
        }

        res.status(200).json({ message: "Video deleted successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" , error:err.message});
    }
});


// Delete an image by ID (and from ImageKit)
router.delete("/api/delete/image/:id" , async (req, res) => {
    try {
        const image = await FactoryImage.findById(req.params.id);
        if (!image) {
            return res.status(404).json({ success: false, message: "Image not found in database" });
        }

        // ✅ Use stored fileId directly — no URL parsing or searching needed
        try {
            await imagekit.deleteFile(image.fileId);
        } catch (ikError) {
            console.error("ImageKit deletion error:", ikError);
            return res.status(500).json({
                success: false,
                message: "Failed to delete image from ImageKit",
                error: ikError.message,
            });
        }

        await FactoryImage.findByIdAndDelete(req.params.id);

        return res.status(200).json({
            success: true,
            message: "Image deleted successfully from both DB and ImageKit",
        });

    } catch (err) {
        console.error("Unexpected server error:", err);
        return res.status(500).json({
            success: false,
            message: "Unexpected server error",
            error: err.message,
        });
    }
});

module.exports  = router;