require("dotenv").config();
const { createClient } = require("redis");

const redisClient = createClient({
  socket: {
    host: process.env.REDIS_HOST || "127.0.0.1",
    port: process.env.REDIS_PORT || 6379,
  },
});

redisClient.on("error", (err) => console.error("❌ Redis Error:", err));

const connectRedis = async () => {
  try {
    await redisClient.connect();
    console.log("✅ Redis connected successfully.");
  } catch (err) {
    console.error("❌ Redis connection failed:", err);
    process.exit(1);
  }
};

module.exports = { redisClient, connectRedis };
