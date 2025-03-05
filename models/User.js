module.exports = (sequelize, DataTypes) => {
  const User = sequelize.define("User", {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    name: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    password: {
      type: DataTypes.STRING,
      allowNull: true, // NULL for Google OAuth users
    },
    provider: {
      type: DataTypes.ENUM("local", "google"),
      defaultValue: "local",
    },
    provider_id: {
      type: DataTypes.STRING,
      allowNull: true, // Only for OAuth users
    },
    email_verified: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
    email_otp_enabled: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
    },
  });

  return User;
};
