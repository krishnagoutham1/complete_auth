const { DataTypes } = require("sequelize");
const { sequelize } = require("../config/db");

const User = sequelize.define(
  "User",
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    password: {
      type: DataTypes.STRING,
      allowNull: true, // Nullable for OAuth users
    },
    name: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    activation_token: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    reset_password_token: {
      type: DataTypes.STRING,
      allowNull: true,
    },

    is_verified: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },

    // Status ENUM instead of BOOLEAN
    status: {
      type: DataTypes.ENUM(
        "pending",
        "active",
        "inactive",
        "deleted",
        "banned"
      ),
      defaultValue: "pending",
    },

    // Role ENUM
    role: {
      type: DataTypes.ENUM(
        "user",
        "admin",
        "moderator",
        "editor",
        "super_admin"
      ),
      defaultValue: "user",
    },

    last_login: {
      type: DataTypes.DATE,
      allowNull: true,
    },
  },
  {
    timestamps: true, // adds createdAt & updatedAt
    paranoid: true, // enables soft deletes (deletedAt)
    tableName: "Users",
  }
);

module.exports = User;
