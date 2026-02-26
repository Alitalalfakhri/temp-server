
const router = require('express').Router();

const imagekit = require('./iamgekit')

const upload = require('./multer')

const dotenv = require('dotenv');

dotenv.config();

const ReviewVideos = require('../models/reviewVideo')

const FactoryVideos = require('../models/factoryVideos')

const FactoryImage = require('../models/factoryImages')


const { body, validationResult } = require('express-validator');

router.post("/api/add/video", async (req, res) =>{
    const videoData = req.body;
   
    if(!videoData.videoType){
        return res.json({message:"no video type "}).status(400)

    }
    if(videoData.videoType === 'review'){
         if(!videoData.videoUrl || !videoData.description){
        return res.json({message:"no video url or description "}).status(400)
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
)

router.post("/api/add/image",  upload.single("image") ,async (req, res) =>{
    
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
})
module.exports  = router;