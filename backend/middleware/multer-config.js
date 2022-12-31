import multer from "multer";
//backup img
/******************** management of files entering HTTP requests******************/
const MIME_TYPES = {
  "image/jpg": "jpg",
  "image/jpeg": "jpg",
  "image/png": "png",
};
/*********diskStorage() configure path and filename for incoming files.************/
const storage = multer.diskStorage({
  destination: (req, file, callback) => {
    callback(null, "images");
  },
  /*replace spaces with underscores and add a timestamp {date} as the original name*/
  filename: (req, file, callback) => {
    const name = file.originalname.split(" ").join("_");
    const extension = MIME_TYPES[file.mimetype];
    /* Rename the file to its original name + date + extension */
    callback(null, name + Date.now() + "." + extension);
  },
});
//single()creates a middleware which captures files of a certain type (passed as an argument),
//logs to server file system using configured storage
export default multer({ storage }).single("image");
