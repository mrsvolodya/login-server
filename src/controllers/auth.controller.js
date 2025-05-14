import bcrypt from "bcrypt";
import { ApiError } from "../exceptions/api.error.js";
import { User } from "../models/user.js";
import { jwtService } from "../services/jwt.service.js";
import { tokenService } from "../services/token.service.js";
import { userService } from "../services/user.service.js";

const EMAIL_PATTERN = /^[\w.+-]+@([\w-]+\.){1,3}[\w-]{2,}$/;

function validateEmail(value) {
  if (!value) return "Email is required";
  if (!EMAIL_PATTERN.test(value)) return "Email is not valid";
}

function validatePassword(value) {
  if (!value) return "Password is required";
  if (value.length < 6) return "At least 6 characters";
}

const register = async (req, res, next) => {
  const { email, password } = req.body;

  const errors = {
    email: validateEmail(email),
    password: validatePassword(password),
  };

  const heshedPassword = await bcrypt.hash(password, 10);

  if (errors.email || errors.password) {
    throw ApiError.badRequest("Bad request", 400, errors);
  }

  await userService.register(email, heshedPassword);

  res.send({ message: "OK" });
};

const activate = async (req, res) => {
  const { activationToken } = req.params;

  const user = await User.findOne({ where: { activationToken } });

  if (!user) {
    res.sendStatus(404);
    return;
  }

  user.activationToken = null;
  user.save();

  res.send(user);
};

const login = async (req, res) => {
  const { email, password } = req.body;
  const user = await userService.findByEmail(email);

  if (!user) {
    throw ApiError.badRequest("No such user");
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    throw ApiError.badRequest("Wrong password");
  }

  await generateTokens(res, user);
};

const refresh = async (req, res) => {
  const { refreshToken } = req.cookies;

  const userData = await jwtService.verifyRefresh(refreshToken);

  const token = await tokenService.getByToken(refreshToken);

  if (!userData || !token) {
    throw ApiError.unauthorized();
  }

  const user = await userService.findByEmail(userData.email);

  generateTokens(res, user);
};

async function generateTokens(res, user) {
  const normalizedUser = userService.normalize(user);
  const accessToken = jwtService.sign(normalizedUser);

  const refreshToken = jwtService.signRefresh(normalizedUser);

  await tokenService.save(normalizedUser.id, refreshToken);

  res.cookie("refreshToken", refreshToken, {
    maxAge: 30 * 24 * 60 * 60 * 1000,
    httpOnly: true,
  });

  res.send({
    user: normalizedUser,
    accessToken,
  });
}

const logout = async (req, res) => {
  const { refreshToken } = req.cookies;
  const userData = await jwtService.verifyRefresh(refreshToken);

  if (!userData || !refreshToken) {
    throw ApiError.unauthorized();
  }

  await tokenService.remove(userData.id);

  res.clearCookie("refreshToken");

  res.sendStatus(204);
};

export const authController = {
  register,
  activate,
  refresh,
  login,
  logout,
};
