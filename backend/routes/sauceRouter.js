import { Router } from "express";
import {
  createSauce,
  deleteSauce,
  getAllSauce,
  getSauceUnity,
  likeSauces,
  modifSauce,
} from "../controllers/sauceController.js";
import { auth } from "../middleware/auth.js";
import multer from "../middleware/multer-config.js";

const router = Router();

/**
 * create
 */
router.post("/", auth, multer, createSauce);
/**
 * modify
 */
router.put("/:id", auth, multer, modifSauce);
/**
 *
 * delete
 */
router.delete("/:id", auth, deleteSauce);
/**
 * recup of a single sauce item
 */
router.get("/:id", auth, getSauceUnity);
/**
 *
 * intercept all sauces
 * (/api/sauces) = http://3000/api/sauces
 */
router.get("/", auth, getAllSauce);

/**
 *
 *like/disliked
 */
router.post("/:id/like", auth, likeSauces);

export default router;
