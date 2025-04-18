require("dotenv").config();
const PORT = process.env.PORT;

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const helmet = require("helmet");
const compression = require("compression");
const jwt = require("jsonwebtoken");

const { connectDB, syncDB } = require("./config/db");
const { connectRedis } = require("./config/redis");

const authRoute = require("./routes/authRoute");

const app = express();

// Middleware
app.use(cors({ origin: process.env.CLIENT_URL, credentials: true }));
app.use(helmet());
app.use(compression());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// Connect Database & Sync Models
connectDB().then(syncDB);
connectRedis(); // Connect to Redis

// Test Route
const verifyAccessToken = require("./middleware/authentations");

app.get("/demo", verifyAccessToken, async (req, res) => {
  res.status(200).json({ message: "hi" });
});

app.get("/test", (req, res) => {
  const token = req.cookies?.accessToken;

  if (!token) {
    return res.status(403).json({ message: "Access token missing" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    return res.status(200).json({
      message: "Authenticated request",
      user: decoded, // contains { id, role, ... }
    });
  } catch (err) {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
});

app.use("/auth", authRoute);

// Start Server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
