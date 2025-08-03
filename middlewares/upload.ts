// middlewares/upload.ts
import multer from 'multer';
import path from 'path';
import fs from 'fs';

// Ensure the folder exists
const uploadPath = 'uploads/verifications';
if (!fs.existsSync(uploadPath)) {
    fs.mkdirSync(uploadPath, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (_req, _file, cb) => {
        cb(null, uploadPath); // ✅ Save under uploads/verifications
    },
    filename: (_req, file, cb) => {
        const ext = path.extname(file.originalname);
        const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`;
        cb(null, uniqueName);
    }
});

export const upload = multer({ storage });
