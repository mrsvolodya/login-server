import { v4 as uuidv4 } from "uuid";
import { ApiError } from "../exceptions/api.error.js";
import { User } from "../models/user.js";
import { emailService } from "../services/email.service.js";
export async function getAllActivated() {
  return User.findAll({
    where: {
      activationToken: null,
    },
  });
}

function normalize({ id, email }) {
  return { id, email };
}

function findByEmail(email) {
  return User.findOne({ where: { email } });
}

async function register(email, password) {
  const activationToken = uuidv4();

  const existingUser = await findByEmail(email);

  if (existingUser) {
    throw ApiError.badRequest(
      "User already exists!",
      409,
      "User already exists!"
    );
  }

  await User.create({ email, password, activationToken });
  await emailService.sendActivationEmail(email, activationToken);
}

export const userService = {
  getAllActivated,
  findByEmail,
  normalize,
  register,
};
