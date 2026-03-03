const mongoose = require('mongoose');

const imagesSchema = new mongoose.Schema({
    imageUrl: {
        type: String,
        required: true
    },
    fileId:{
        type: String,
        required: true
    },
    title:{
        type:String,
        required:false
    }

})

const FactoryImage = mongoose.model('factoryImage', imagesSchema);

module.exports = FactoryImage;