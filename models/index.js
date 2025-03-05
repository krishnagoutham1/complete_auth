const { Sequelize } = require("sequelize");
const { sequelize } = require("../config/db");

// Load models
const User = require("./User");

// Initialize models
const db = {
  sequelize,
  Sequelize,
  User: User(sequelize, Sequelize),
};

// Sync all models
const syncDB = async () => {
  await sequelize.sync({ alter: true }); // Automatically sync database changes
  console.log("✅ All models synchronized.");
};

module.exports = { db, syncDB };
