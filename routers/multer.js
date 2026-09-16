const multer = require("multer");
const path = require("path");
const fs = require("fs");

const createStorage = (uploadPath) => {
  if (!fs.existsSync(uploadPath)) {
    fs.mkdirSync(uploadPath, { recursive: true });
  }

  return multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, uploadPath);
    },

    filename: (req, file, cb) => {
      const uniqueName =
        Date.now() +
        "-" +
        Math.round(Math.random() * 1e9) +
        path.extname(file.originalname);

      cb(null, uniqueName);
    },
  });
};

const createUpload = (uploadPath) => multer({
  storage: createStorage(uploadPath),

  limits: {
    fileSize: 25 * 1024 * 1024, // 25MB
  },

  fileFilter: (req, file, cb) => {
        const allowedExtensions = [".jpg", ".jpeg", ".png", ".webp"];

        const extension = path
            .extname(file.originalname)
            .toLowerCase();

        if (!allowedExtensions.includes(extension)) {
            return cb(new Error("Only image files are allowed"));
        }

        cb(null, true);
    },
});

const upload = createUpload(path.join(__dirname, "../uploads/products"));
const libraryUpload = createUpload(path.join(__dirname, "../uploads/library"));

module.exports = upload;
module.exports.libraryUpload = libraryUpload;