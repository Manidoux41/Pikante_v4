/***************imports ********************/
import express from "express";
import * as url from "url";
import helmet from "helmet";
import cors from "cors";
import path from "path";
import morgan from "morgan";
import "./config/db.js";

import sauceRoutes from "./routes/sauceRouter.js";
import userRoutes from "./routes/userRouter.js";

const app = express();
const __dirname = url.fileURLToPath(new URL(".", import.meta.url));

/**************************Middlewares***************************** */
app.use(morgan("dev"));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());
app.use("/images", express.static(path.join(__dirname, "images")));

/**********************************Routes**************************/
app.use("/api/sauces", sauceRoutes);
app.use("/api/auth", userRoutes);

export default app;