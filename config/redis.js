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

    // Set a value in Redis with expiration time of 5 minutes (300 seconds)
    await redisClient.set("testKey", "connected to redis db", {
      EX: 300, // 300 seconds = 5 minutes
    });

    // Optionally, get and log the value to verify
    const value = await redisClient.get("testKey");
    console.log(`🔍 Retrieved value: ${value}`);
  } catch (err) {
    console.error("❌ Redis connection failed:", err);
    process.exit(1);
  }
};

module.exports = { redisClient, connectRedis };
