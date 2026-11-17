import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import express from "express";
import mongoose from "mongoose";
import User from "./db/db.js";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const mongoUri = process.env.MONGODB_URI?.trim();

app.use(express.json({ limit: "10kb" }));

function isValidCredentialsBody(body) {
  return body !== null && typeof body === "object" && !Array.isArray(body);
}

function sendUserResponse(user, response, status = 200) {
  return response.status(status).json({
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
    },
  });
}

app.get("/", (_request, response) => {
  response.send("test");
});

app.post("/register", async (request, response) => {
  if (!isValidCredentialsBody(request.body)) {
    return response.status(400).json({ message: "Invalid request body" });
  }

  const { username, email, password } = request.body;

  if (
    typeof username !== "string" ||
    username.trim().length < 3 ||
    username.trim().length > 30 ||
    typeof email !== "string" ||
    email.trim().length === 0 ||
    email.trim().length > 254 ||
    typeof password !== "string" ||
    password.length < 8 ||
    Buffer.byteLength(password, "utf8") > 72
  ) {
    return response.status(400).json({
      message:
        "Provide a username (3-30 characters), email, and password (8-72 bytes)",
    });
  }

  const normalizedUsername = username.trim();
  const normalizedEmail = email.trim().toLowerCase();
  const existingUser = await User.findOne({
    $or: [{ username: normalizedUsername }, { email: normalizedEmail }],
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
  throw new Error("MONGODB_URI must be set before starting the server");
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
