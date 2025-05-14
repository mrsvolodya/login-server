import cookieParser from "cookie-parser";
import cors from "cors";
import "dotenv/config";
import express from "express";
import swaggerJsdoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";
import { errorMiddleware } from "./middlewares/errorMiddleware.js";
import { authRouter } from "./routes/auth.route.js";
import { userRouter } from "./routes/user.route.js";
const PORT = process.env.PORT || 3005;
const app = express();
app.use(
  cors({
    origin: process.env.CLIENT_HOST,
    credentials: true,
  })
);

app.use(express.json());
const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "My Login API",
      version: "1.0.0",
      description: "A simple API for user login and registration",
    },
    servers: [
      {
        url: "http://localhost:3005", // Change if your server runs elsewhere
      },
    ],
  },
  apis: ["./src/routes/*.js", "./src/controllers/*.js"], // Adjust if your routes/controllers are elsewhere
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.use(cookieParser());
app.use("/", authRouter);
app.use("/users", userRouter);

app.get("/", (req, res) => {
  res.send("Hello");
});

app.use(errorMiddleware);

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Swagger docs at http://localhost:${PORT}/api-docs`);
});
