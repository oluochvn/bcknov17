import bcrypt from "bcryptjs";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET;
const mongoUri = process.env.MONGODB_URI?.trim();
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      trim: true,
      minlength: 3,
      maxlength: 30,
    },
    email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
      maxlength: 254,
    },
    passwordHash: {
      type: String,
      required: true,
      select: false,
    },
  },
  { timestamps: true }
);

userSchema.index({ username: 1 }, { unique: true });
userSchema.index({ email: 1 }, { unique: true });

const User = mongoose.model("User", userSchema);

app.set("trust proxy", 1);
app.use(
  cors({
    origin: process.env.FRONTEND_ORIGIN || "http://localhost:5173",
  })
);
app.use(express.json({ limit: "10kb" }));

function isValidCredentialsBody(body) {
  return body !== null && typeof body === "object" && !Array.isArray(body);
}

function createAuthResponse(user, response, status = 200) {
  const token = jwt.sign({ sub: user.id }, jwtSecret, {
    algorithm: "HS256",
    expiresIn: "1h",
  });

  return response.status(status).json({
    token,
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
    email.trim().length > 254 ||
    !emailPattern.test(email.trim()) ||
    typeof password !== "string" ||
    password.length < 8 ||
    Buffer.byteLength(password, "utf8") > 72
  ) {
    return response.status(400).json({
      message:
        "Provide a username (3-30 characters), valid email, and password (8-72 bytes)",
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

  try {
    const user = await User.create({
      username: normalizedUsername,
      email: normalizedEmail,
      passwordHash: await bcrypt.hash(password, 12),
    });

    return createAuthResponse(user, response, 201);
  } catch (error) {
    if (error.code === 11000) {
      return response
        .status(409)
        .json({ message: "Email or username is already registered" });
    }

    throw error;
  }
});

app.post("/login", async (request, response) => {
  if (!isValidCredentialsBody(request.body)) {
    return response.status(400).json({ message: "Invalid request body" });
  }

  const { email, password } = request.body;

  if (
    typeof email !== "string" ||
    !emailPattern.test(email.trim()) ||
    typeof password !== "string" ||
    password.length === 0
  ) {
    return response
      .status(400)
      .json({ message: "Provide a valid email and password" });
  }

  const user = await User.findOne({ email: email.trim().toLowerCase() }).select(
    "+passwordHash"
  );

  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return response.status(401).json({ message: "Invalid email or password" });
  }

  return createAuthResponse(user, response);
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

if (!jwtSecret || Buffer.byteLength(jwtSecret, "utf8") < 32) {
  throw new Error("JWT_SECRET must be set to a secret of at least 32 bytes");
}

try {
  await mongoose.connect(mongoUri, { serverSelectionTimeoutMS: 10000 });
  await User.init();

  app.listen(port, () => {
    console.log(`Connected to MongoDB (${mongoose.connection.name})`);
    console.log(`Server running on port ${port}`);
  });
} catch (error) {
  console.error("Failed to connect to MongoDB:", error.message);
  process.exitCode = 1;
}
