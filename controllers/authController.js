const User = require("../models/User");
const {
  verification_email,
  welcome_email,
  login_otp_email,
} = require("../utils/sendEmail");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const generateOtp = require("../utils/generateOtp");
const { redisClient } = require("../config/redis");

const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ message: "name, email and password are required" });
    }

    const existingUser = await User.findOne({ where: { email } });

    if (existingUser)
      return res.status(400).json({ message: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({
      name,
      email,
      password: hashedPassword,
    });

    const activationToken = jwt.sign(
      { id: newUser.id },
      process.env.JWT_ACTIVATION_SECRET,
      { expiresIn: "10m" }
    );

    const verifyURL = `${process.env.FRONTEND_URL}/verify/${activationToken}`;

    await verification_email({
      to: email,
      name: name,
      verification_link: verifyURL,
    });

    return res.status(201).json({
      message:
        "User registered! Please check your email to activate your account.",
      data: { name, email },
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Internal Server Error", error: err });
  }
};

const verifyEmail = async (req, res) => {
  try {
    const { token } = req.params;

    const decodedToken = await jwt.verify(
      token,
      process.env.JWT_ACTIVATION_SECRET
    );

    console.log(decodedToken);

    const user = await User.findByPk(decodedToken.id);

    console.log(user);

    if (user.is_verified) {
      return res
        .status(400)
        .json({ message: "Account already verified pls login" });
    }

    user.is_verified = true;
    user.status = "active";

    await user.save();

    await welcome_email({
      to: user.email,
      name: user.name,
    });

    return res.json({
      message: "Account verification successful pls login to continue",
    });
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(400).json({
        message: "Token has expired, please request a new verification email.",
      });
    } else if (err.name === "JsonWebTokenError") {
      return res.status(400).json({
        message: "Invalid token, please request a new verification email.",
      });
    } else {
      console.error(err);
      return res
        .status(500)
        .json({ message: "Internal Server Error", error: err });
    }
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "email and password are required" });
    }

    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(404).json({ message: "No user Found!!!" });
    }

    if (user.is_deleted) {
      return res
        .status(403)
        .json({ message: "This account has been deactivated" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid Credentials" });
    }

    if (!user.is_verified) {
      return res
        .status(403)
        .json({ message: "Please Activate your account to login" });
    }

    if (user.otp_login) {
      const login_otp = generateOtp();

      await login_otp_email({
        to: email,
        otp: login_otp,
      });

      await redisClient.set(`${user.id}:loginOtp`, login_otp, { EX: 900 });
      await redisClient.del(`${user.id}:otpAttempt`);
      await redisClient.del(`${user.id}:resendOtpAttempt`);
      await redisClient.del(`${user.id}:resedOtpAttemptCooldown`);

      return res
        .status(200)
        .json({ message: "Otp sent successfully", id: user.id });
    } else {
      const previous_login = user.last_login;

      user.last_login = new Date();
      await user.save();

      return res.status(200).json({
        message: "login successfull",
        data: {
          name: user.name,
          email: user.email,
          role: user.role,
          status: user.status,
          last_login: new Date(previous_login).toLocaleString("en-IN", {
            timeZone: "Asia/Kolkata",
          }),
        },
      });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Internal Server Error", error: err });
  }
};

const verifyLoginOtp = async (req, res) => {
  try {
    const { userId, otp } = req.body;

    if (!userId || !otp) {
      return res.status(400).json({ message: "missing fields userid and otp" });
    }

    const [existingOtp, user, otpAttempts] = await Promise.all([
      redisClient.get(`${userId}:loginOtp`),
      User.findByPk(userId),
      redisClient.get(`${userId}:otpAttempt`),
    ]);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (otpAttempts && parseInt(otpAttempts) >= 3) {
      return res.status(429).json({ message: "max attempts reached" });
    }

    if (!existingOtp) {
      return res.status(400).json({ message: "OTP expired or not found" });
    }

    if (existingOtp === otp) {
      const previous_login = user.last_login;
      user.last_login = new Date();

      await Promise.all([
        user.save(),
        redisClient.del(`${userId}:loginOtp`),
        redisClient.del(`${userId}:otpAttempt`),
      ]);

      return res.status(200).json({
        message: "login successfull",
        data: {
          name: user.name,
          email: user.email,
          role: user.role,
          last_login: new Date(previous_login).toLocaleString("en-IN", {
            timeZone: "Asia/Kolkata",
          }),
        },
      });
    } else {
      const newAttempts = otpAttempts ? parseInt(otpAttempts) + 1 : 1;

      await redisClient.set(`${userId}:otpAttempt`, newAttempts, { EX: 900 });

      return res.status(400).json({
        message: "incorrect otp,pls enter correct one",
        attemptsLeft: 3 - newAttempts,
      });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Internal Server Error", error: err });
  }
};

const resendLoginOtp = async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) {
      return res.status(400).json({ message: "User ID is required." });
    }

    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    const existingOtp = await redisClient.get(`${userId}:loginOtp`);
    if (!existingOtp) {
      return res.status(404).json({
        message: "OTP expired or not found. Please initiate login again.",
      });
    }

    const otpAttemptsKey = `${userId}:resendOtpAttempt`;
    const otpCooldownKey = `${userId}:resedOtpAttemptCooldown`;

    const cooldownTTL = await redisClient.ttl(otpCooldownKey);
    console.log(cooldownTTL);
    if (cooldownTTL > 0) {
      return res.status(429).json({
        message: `Please wait ${cooldownTTL} seconds before resending OTP.`,
      });
    }

    let otpAttempts = await redisClient.get(otpAttemptsKey);
    otpAttempts = otpAttempts ? parseInt(otpAttempts) : 0;

    if (otpAttempts >= 3) {
      return res.status(429).json({
        message: "Maximum resend attempts reached. Please try again later.",
      });
    }

    await redisClient.set(otpAttemptsKey, otpAttempts + 1, { EX: 900 }); // Expires in 15 minutes
    await redisClient.set(otpCooldownKey, "true", { EX: 60 }); // Cooldown period of 60 seconds

    // await login_otp_email({
    //   to: user.email,
    //   otp: existingOtp,
    // });

    return res.status(200).json({ message: "OTP resent successfully." });
  } catch (err) {
    console.error("Error resending OTP:", err);
    return res
      .status(500)
      .json({ message: "Internal Server Error", error: err.message });
  }
};

module.exports = {
  register,
  login,
  verifyEmail,
  verifyLoginOtp,
  resendLoginOtp,
};
