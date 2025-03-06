require("dotenv").config();
const PORT = process.env.PORT;

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const helmet = require("helmet");
const compression = require("compression");

const { connectDB } = require("./config/db");
const { syncDB } = require("./models");
const { connectRedis } = require("./config/redis");

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
app.get("/", (req, res) => {
  res.send("Authentication API is running...");
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
