import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import express from "express";
import mongoose from "mongoose";
import User from "./db/db.js";

const app = express();
const port = process.env.PORT || 3000;

dotenv.config();

app.use(express.json());

const isValidCredentialsBody = (body) =>
  body &&
  typeof body === "object" &&
  typeof body.email === "string" &&
  typeof body.password === "string";

const sendUserResponse = (user, response, statusCode = 200) => {
  return response.status(statusCode).json({
    id: user._id,
    username: user.username,
    email: user.email,
  });
};

app.get("/", (_request, response) => {
  response.send("test");
});

const mongoUri = process.env.MONGODB_URI;

app.post("/register", async (request, response) => {
  if (!isValidCredentialsBody(request.body)) {
    return response.status(400).json({ message: "Invalid request body" });
  }

  const { username, email, password } = request.body;

  if (!username || !email || !password || password < 6){
    return response.status(400).json({
      message: "Enter username, email, and a password with at least 6 characters",
    });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const normalizedUsername = username.trim();
  const existingUser = await User.findOne({
    $or: [{ email: normalizedEmail }, { username: normalizedUsername }],
  });

  if (existingUser) {
    return response
      .status(409)
      .json({ message: "Email or username is already registered" });
  }

  const user = await User.create({
    username: normalizedUsername,
    email: normalizedEmail,
    passwordHash: await bcrypt.hash(password, 12),
  });

  return sendUserResponse(user, response, 201);
});

app.post("/login", async (request, response) => {
  if (!isValidCredentialsBody(request.body)) {
    return response.status(400).json({ message: "Invalid request body" });
  }

  const { email, password } = request.body;

  if (
    typeof email !== "string" ||
    email.trim().length === 0 ||
    typeof password !== "string" ||
    password.length === 0
  ) {
    return response
      .status(400)
      .json({ message: "Provide an email and password" });
  }

  const user = await User.findOne({ email: email.trim().toLowerCase() }).select(
    "+passwordHash"
  );

  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return response.status(401).json({ message: "Invalid email or password" });
  }

  return sendUserResponse(user, response);
});

app.use((error, _request, response, next) => {
  console.error(error);
  if (response.headersSent) {
    return next(error);
  }
  return response.status(500).json({ message: "Internal server error" });
});

if (!mongoUri) {
  throw new Error("server err");
}

try {
  await mongoose.connect(mongoUri, { serverSelectionTimeoutMS: 10000 });

  app.listen(port, () => {
    console.log(`Connected to MongoDB (${mongoose.connection.name})`);
    console.log(`Server running on port ${port}`);
  });
} catch (error) {
  console.error("Failed to connect to MongoDB:", error.message);
  process.exitCode = 1;
}
