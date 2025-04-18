const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { v4: uuidv4 } = require("uuid");

const User = require("../models/User");
const { redisClient } = require("../config/redis");
const RedisKeys = require("../utils/redisKeys");

const generateOtp = require("../utils/generateOtp");
const {
  sendVerificationEmail,
  sendWelcomeEmail,
  sendLoginOtpEmail,
  sendResetPasswordEmail,
} = require("../utils/sendEmail");
const {
  generateAccessToken,
  generateRefreshToken,
  generateEmailVerificationToken,
  generateResetPasswordToken,
} = require("../utils/tokens");
const {
  updatePasswordUrl,
  emailVerificationUrl,
  dashboardUrl,
} = require("../utils/page_constants");
const { REDIS_EXPIRY, COOKIE_AGE } = require("../utils/constants");
const {
  setAccessTokenCookie,
  setUserIdCookie,
  setRefreshIdCookie,
} = require("../utils/cookies");

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
      return res.status(400).json({
        message: !existingUser.is_verified
          ? "Verification pending"
          : "Email already exists",
      });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({
      name,
      email,
      password: hashedPassword,
    });

    const activationToken = generateEmailVerificationToken({ id: newUser.id });

    const verificationLink = emailVerificationUrl(activationToken);

    await sendVerificationEmail({
      to: email,
      name: name,
      verification_link: verificationLink,
    });

    return res.status(201).json({
      message:
        "User registered! Please check your email to activate your account.",
      data: { name, email },
      success: true,
    });
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error", error: err });
  }
};

const verifyEmail = async (req, res) => {
  try {
    const { token } = req.params;

    const decodedToken = jwt.verify(
      token,
      process.env.JWT_EMAIL_VERIFICATION_SECRET
    );

    const user = await User.findByPk(decodedToken.id);

    if (!user) {
      return res
        .status(404)
        .json({ message: "User not found or Invalid Token" });
    }

    if (user.is_verified) {
      return res.status(400).json({
        message: "Account already verified please login",
        showLogin: true,
      });
    }

    user.is_verified = true;
    user.status = "active";

    await user.save();

    await sendWelcomeEmail({
      to: user.email,
      name: user.name,
      dashboard_link: dashboardUrl,
    });

    return res.json({
      message: "Account verification successful pls login to continue",
      success: true,
    });
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      const decoded = jwt.decode(req.params.token);

      if (decoded?.id) {
        const user = await User.findByPk(decoded.id);
        if (user?.is_verified) {
          return res.status(400).json({
            message: "Account already verified. Please login.",
            showLogin: true,
          });
        }
      }

      return res.status(401).json({
        message: "Token has expired, please request a new verification email.",
        expired: true,
      });
    } else if (err.name === "JsonWebTokenError") {
      return res.status(400).json({
        message: "Invalid token, please request a new verification email.",
      });
    } else {
      return res
        .status(500)
        .json({ message: "Internal Server Error", error: err });
    }
  }
};

const resendVerificationEmail = async (req, res) => {
  try {
    const { email } = req.body;

    const existingEmail = await User.findOne({ where: { email } });

    if (!existingEmail) {
      return res.status(400).json({ message: "No user found ,pls register" });
    }

    if (existingEmail.is_verified) {
      return res
        .status(400)
        .json({ message: "User already verified pls login" });
    }

    const activationToken = generateEmailVerificationToken({
      id: existingEmail.id,
    });

    const verificationLink = emailVerificationUrl(activationToken);

    await sendVerificationEmail({
      to: email,
      name: existingEmail.name,
      verification_link: verificationLink,
    });

    return res.status(201).json({
      message:
        "New link sent successfully! Please check your email to activate your account.",
      data: { name: existingEmail.name, email },
      success: true,
    });
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error", error: err });
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

      await sendLoginOtpEmail({
        to: email,
        name: user.name,
        otp: login_otp,
      });

      await redisClient.set(RedisKeys.LOGIN_OTP(user.id), login_otp, {
        EX: REDIS_EXPIRY.LOGIN_OTP,
      });

      await redisClient.del(RedisKeys.LOGIN_OTP_ATTEMPT(user.id));
      await redisClient.del(RedisKeys.RESEND_OTP_ATTEMPT(user.id));
      await redisClient.del(RedisKeys.RESEND_OTP_COOLDOWN(user.id));

      return res.status(200).json({
        message: "Otp sent successfully",
        id: user.id,
        test: login_otp,
        otp: true,
        success: true,
      });
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
          otp: false,
          last_login: previous_login
            ? new Date(previous_login).toLocaleString("en-IN", {
                timeZone: "Asia/Kolkata",
              })
            : null,
          success: true,
        },
      });
    }
  } catch (err) {
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
      redisClient.get(RedisKeys.LOGIN_OTP(userId)),
      User.findByPk(userId),
      redisClient.get(RedisKeys.LOGIN_OTP_ATTEMPT(userId)),
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
        redisClient.del(RedisKeys.LOGIN_OTP(userId)),
        redisClient.del(RedisKeys.LOGIN_OTP_ATTEMPT(userId)),
      ]);

      const accessToken = generateAccessToken({ id: user.id, role: user.role });

      setAccessTokenCookie(res, accessToken);

      setUserIdCookie(res, userId);

      const refreshId = uuidv4();

      setRefreshIdCookie(res, refreshId);

      const refreshToken = generateRefreshToken({ id: user.id });

      const sessionMeta = {
        refresh: refreshToken,
        userAgent: req.headers["user-agent"] || null,
        ip: req.ip,
      };

      await redisClient.set(
        RedisKeys.REFRESH_TOKEN_ID({ userId, refreshId }),
        JSON.stringify(sessionMeta),
        {
          EX: REDIS_EXPIRY.REFRESH_TOKEN_ID,
        }
      );

      return res.status(200).json({
        message: "login successfull",
        data: {
          name: user.name,
          email: user.email,
          role: user.role,
          last_login: previous_login
            ? new Date(previous_login).toLocaleString("en-IN", {
                timeZone: "Asia/Kolkata",
              })
            : null,
        },
        success: true,
      });
    } else {
      const newAttempts = otpAttempts ? parseInt(otpAttempts) + 1 : 1;

      await redisClient.set(RedisKeys.LOGIN_OTP_ATTEMPT(userId), newAttempts, {
        EX: REDIS_EXPIRY.LOGIN_OTP_ATTEMPT,
      });

      return res.status(400).json({
        message: "incorrect otp,pls enter correct one",
        attemptsLeft: 3 - newAttempts,
      });
    }
  } catch (err) {
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

    const existingOtp = await redisClient.get(RedisKeys.LOGIN_OTP(userId));

    if (!existingOtp) {
      return res.status(404).json({
        message: "OTP expired or not found. Please initiate login again.",
        initiateLogin: true,
      });
    }

    const otpAttemptsKey = RedisKeys.RESEND_OTP_ATTEMPT(userId);
    const otpCooldownKey = RedisKeys.RESEND_OTP_COOLDOWN(userId);

    const cooldownTTL = await redisClient.ttl(otpCooldownKey);

    if (cooldownTTL > 0) {
      return res.status(429).json({
        message: `Please wait ${cooldownTTL} seconds before resending OTP.`,
      });
    }
    // check any chance of -2 then write esle === -2 ...
    let otpAttempts = await redisClient.get(otpAttemptsKey);
    otpAttempts = otpAttempts ? parseInt(otpAttempts) : 0;

    if (otpAttempts >= 3) {
      return res.status(429).json({
        message: "Maximum resend attempts reached. Please try again later.",
      });
    }

    await redisClient.set(
      RedisKeys.RESEND_OTP_ATTEMPT(userId),
      otpAttempts + 1,
      { EX: REDIS_EXPIRY.RESEND_OTP_ATTEMPT }
    );

    await redisClient.set(RedisKeys.RESEND_OTP_COOLDOWN(userId), "true", {
      EX: REDIS_EXPIRY.RESEND_OTP_COOLDOWN,
    });

    await sendLoginOtpEmail({
      to: user.email,
      name: user.name,
      otp: existingOtp,
    });

    return res
      .status(200)
      .json({ message: "OTP resent successfully.", success: true }); // missing otp left add this
  } catch (err) {
    return res
      .status(500)
      .json({ message: "Internal Server Error", error: err.message });
  }
};

const sendResetPasswordLink = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!user.is_verified) {
      return res.status(400).json({
        message: "Please verify your account to proceed with password reset.",
      });
    }

    const resetToken = generateResetPasswordToken({ id: user.id });

    const resetLink = updatePasswordUrl(resetToken);

    await sendResetPasswordEmail({
      to: email,
      name: user.name,
      reset_link: resetLink,
    });

    return res.status(200).json({
      message: "Password reset link has been sent to your email.",
      success: true,
      test: resetLink,
    });
  } catch (err) {
    return res
      .status(500)
      .json({ message: "Internal Server Error", error: err });
  }
};

const updatePassword = async (req, res) => {
  try {
    const { token, confirmPassword, password } = req.body;

    if (!token || !confirmPassword || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const decodedToken = jwt.verify(
      token,
      process.env.JWT_RESET_PASSWORD_SECRET
    );

    const checkTokenStatus = await redisClient.get(
      RedisKeys.INVALIDATED_TOKEN(token)
    );

    if (checkTokenStatus) {
      return res
        .status(400)
        .json({ message: "This reset link has already been used" });
    }

    const user = await User.findByPk(decodedToken.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }

    const isSameAsOld = await bcrypt.compare(password, user.password);

    if (isSameAsOld) {
      return res.status(400).json({
        message: "New password cannot be the same as the old password",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    await user.save();

    await redisClient.set(RedisKeys.INVALIDATED_TOKEN(token), "invalid", {
      EX: REDIS_EXPIRY.INVALIDATED_TOKEN,
    });

    return res
      .status(200)
      .json({ message: "Password updated successfully", success: true });
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Reset link has expired" });
    } else if (err.name === "JsonWebTokenError") {
      return res.status(400).json({
        message: "Invalid token, please request a new verification email.",
      });
    } else {
      return res
        .status(500)
        .json({ message: "Internal Server Error", error: err.message });
    }
  }
};

const logout = () => {};

module.exports = {
  register,
  verifyEmail,
  resendVerificationEmail,
  login,
  verifyLoginOtp,
  resendLoginOtp,
  sendResetPasswordLink,
  updatePassword,
  logout,
};
