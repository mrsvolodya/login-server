import express from "express";
import { authController } from "../controllers/auth.controller.js";
import { catchError } from "../utils/catchError.js";
export const router = new express.Router();

router.post("/registration", catchError(authController.register));
router.get("/activation/:activationToken", catchError(authController.activate));
router.post("/login", catchError(authController.login));
router.get("/refresh", catchError(authController.refresh));
router.post("/logout", catchError(authController.logout));

export { router as authRouter };
