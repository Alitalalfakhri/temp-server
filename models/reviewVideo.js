const mongoose = require('mongoose');

const reviewVideoSCchema = new mongoose.Schema({
    videoUrl: {
        type: String,
        required: true
    },
    description: {
        type: String,
        required: false
    },
    role:{
        type: String,
        required: false
    
    },
    company:{
        type:String,
        required:false
    
    }

})


const ReviewVideos = mongoose.model('reviewVideos', reviewVideoSCchema);

module.exports = ReviewVideos;