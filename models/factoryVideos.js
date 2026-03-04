const mongoose = require('mongoose');

const factoryVideosSchema = new mongoose.Schema({
    videoUrl: {
        type: String,
        required: true
    },
    title:{
        type:String,
        required:false
    }
});

const FactoryVideo = mongoose.model('FactoryVideo', factoryVideosSchema);

module.exports = FactoryVideo;