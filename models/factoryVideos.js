const mongoose = require('mongoose');

const factoryVideosSchema = new mongoose.Schema({
    videoUrl: {
        type: String,
        required: true
    }
});

const FactoryVideo = mongoose.model('FactoryVideo', factoryVideosSchema);

module.exports = FactoryVideo;