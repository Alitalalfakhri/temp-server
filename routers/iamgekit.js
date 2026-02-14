const ImageKit = require("imagekit");
const dotenv = require("dotenv");

dotenv.config();

const imagekit = new ImageKit({
  publicKey: 'public_m1+4veR+sFjoO+5jHKiBRuLA544=',
  privateKey: 'private_HpLa9wr+fnJ68e0e0xUM2HagKMA=',
  urlEndpoint: 'https://ik.imagekit.io/rcimzxqih',
});

module.exports = imagekit;
