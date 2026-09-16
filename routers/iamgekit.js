const ImageKit = require("imagekit");
const dotenv = require("dotenv");

dotenv.config();

const imagekitConfig = {
  publicKey: process.env.IMAGEKIT_PUBLIC_KEY,
  privateKey: process.env.IMAGEKIT_PRIVATE_KEY,
  urlEndpoint: process.env.IMAGEKIT_URL_ENDPOINT,
};

const imagekit = Object.values(imagekitConfig).every(Boolean)
  ? new ImageKit(imagekitConfig)
  : new Proxy({}, {
      get() {
        return () => Promise.reject(new Error('ImageKit is not configured'));
      },
    });

module.exports = imagekit;
