const mongoose = require('mongoose');

const imagesSchema = new mongoose.Schema({
    imageUrl: {
        type: String,
        required: true
    }

})

const FactoryImage = mongoose.model('factoryImage', imagesSchema);

module.exports = FactoryImage;