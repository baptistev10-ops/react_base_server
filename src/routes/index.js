import express from "express";

import userRoutes from "./user.route.js";
import blogRoutes from "./blog.route.js";

const router = express.Router();

router.use("/blog", blogRoutes);

router.use("/user", userRoutes);

export default router;
