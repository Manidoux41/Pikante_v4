import { Router } from "express";
import { signup, login } from "../controllers/userController.js";
import password from "../middleware/password.js";

const router = Router();

router.post("/signup", password, signup);
router.post("/login", login);

export default router;
